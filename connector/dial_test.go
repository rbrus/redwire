package connector

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rbrus/redwire/ssrf"
)

// Every other test in this package points a connector at an httptest server, which binds 127.0.0.1
// — a private address, and therefore one the default transport now refuses. Those tests are the
// self-host case in miniature: a target we deliberately chose on loopback. They say so by asking
// for the unpinned transport by name, which is exactly the discipline the production call sites owe.
func loopbackClient() *http.Client { return PrivateTargetClient(5 * time.Second) }

func loopbackWSDialer() *websocket.Dialer { return PrivateTargetWSDialer(5 * time.Second) }

func TestANilClientIsGuardedNotPlain(t *testing.T) {
	// The direction of the default is the whole point. An opt-in guard reads identically in review
	// and behaves like no guard in production, so this pins which way round it is.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"response":"ya29.INSTANCE-CREDENTIAL"}`))
	}))
	defer srv.Close()

	cfg := Config{
		Endpoint:        srv.URL,
		Auth:            Auth{Type: AuthNone},
		RequestMapping:  Mapping{MessageField: "message"},
		ResponseMapping: Mapping{MessageField: "response"},
	}

	if _, err := NewREST(cfg, nil).Send(context.Background(), "x"); err == nil {
		t.Error("REST with a nil client reached loopback")
	} else if !strings.Contains(err.Error(), "Private/internal") {
		t.Errorf("REST refused for the wrong reason: %v", err)
	}
	if _, err := NewA2A(srv.URL, Auth{Type: AuthNone}, nil).Send(context.Background(), "x"); err == nil {
		t.Error("A2A with a nil client reached loopback")
	}
	if _, err := NewMCP(srv.URL, Auth{Type: AuthNone}, nil).Send(context.Background(), "x"); err == nil {
		t.Error("MCP with a nil client reached loopback")
	}

	// The control: naming the unpinned transport reaches it, so the three refusals above are the
	// guard and not a server that was never listening.
	got, err := NewREST(cfg, loopbackClient()).Send(context.Background(), "x")
	if err != nil || got != "ya29.INSTANCE-CREDENTIAL" {
		t.Fatalf("the opt-out path should still reach a private target: %q %v", got, err)
	}
}

// publicResolver makes a name the test controls look like ordinary public space to the ssrf guard,
// so a hop to it passes every address and name check and the only thing that can refuse it is the
// rule about what the hop would carry.
type publicResolver struct{}

func (publicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
}

func TestATargetCannotRedirectTheAPIKeyOrThePayloadToAnotherHost(t *testing.T) {
	// The rule behind ssrf.checkSameHost, pinned on the path that actually carries a secret: an
	// api_key target sends its credential under a header the CALLER named, so none of net/http's
	// Authorization-stripping applies, and a 307 replays the body — which is the payload. A
	// compromised target must not be able to redirect either to a host of its choosing.
	saved := ssrf.DefaultResolver
	ssrf.DefaultResolver = publicResolver{}
	t.Cleanup(func() { ssrf.DefaultResolver = saved })

	type carried struct{ key, body string }
	got := make(chan carried, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		got <- carried{key: r.Header.Get("X-API-Key"), body: string(b)}
	}))
	defer collector.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://collector.example/collect", http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	// Both hops reach a real listener — the connect-time pin is out of the way — so the redirect
	// rule is the only thing left that can refuse this.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "collector.example:") {
			address = collector.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: ssrf.CheckRedirect}

	cfg := Config{
		Endpoint:        target.URL,
		Auth:            Auth{Type: AuthAPIKey, APIKeyHeader: "X-API-Key", APIKeyValue: "CUSTOMER-AGENT-CREDENTIAL"},
		RequestMapping:  Mapping{MessageField: "input.text"},
		ResponseMapping: Mapping{MessageField: "response"},
	}
	_, err := NewREST(cfg, client).Send(context.Background(), "PROPRIETARY-ATTACK-TEMPLATE")

	select {
	case c := <-got:
		t.Fatalf("a redirect handed another host key=%q body=%q", c.key, c.body)
	default:
	}
	if err == nil {
		t.Fatal("the cross-host redirect was followed")
	}
}

// TestThePrivateTargetClientStillRefusesAHostChangingRedirect pins the split the escape hatch used
// to lose: opting into a PRIVATE ADDRESS is not opting into handing the credential to a third host.
//
// This runs through the client the CLI's buildTarget and the self-host dashboard hand every
// transport, with no test-supplied dialer and no fake resolver — both hops are names the operating
// system really resolves, so nothing but the redirect rule stands between the target and the
// collector.
func TestThePrivateTargetClientStillRefusesAHostChangingRedirect(t *testing.T) {
	type carried struct{ key, body string }
	got := make(chan carried, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		got <- carried{key: r.Header.Get("X-API-Key"), body: string(b)}
	}))
	defer collector.Close()

	// httptest binds 127.0.0.1; "localhost" reaches the same listener under a DIFFERENT host, which
	// is what makes this a host change the operating system will happily follow.
	_, collectorPort, err := net.SplitHostPort(collector.Listener.Addr().String())
	if err != nil {
		t.Fatalf("read the collector address: %v", err)
	}
	elsewhere := "http://localhost:" + collectorPort + "/collect"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere, http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	cfg := Config{
		Endpoint:        target.URL,
		Auth:            Auth{Type: AuthAPIKey, APIKeyHeader: "X-API-Key", APIKeyValue: "CUSTOMER-AGENT-CREDENTIAL"},
		RequestMapping:  Mapping{MessageField: "input.text"},
		ResponseMapping: Mapping{MessageField: "response"},
	}
	_, err = NewREST(cfg, PrivateTargetClient(5*time.Second)).Send(context.Background(), "PROPRIETARY-ATTACK-TEMPLATE")

	select {
	case c := <-got:
		t.Fatalf("the private-target client handed another host key=%q body=%q", c.key, c.body)
	default:
	}
	if err == nil {
		t.Fatal("the private-target client followed a cross-host redirect")
	}
}

// TestThePrivateTargetClientStillFollowsARedirectWithinTheTarget is the other half: the escape hatch
// exists so a self-host operator can scan their own agent, and a guard that breaks that gets switched
// off. A target moving the scan to another port of itself is the ordinary shape on loopback.
func TestThePrivateTargetClientStillFollowsARedirectWithinTheTarget(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"response":"pong"}`))
	}))
	defer real.Close()

	_, realPort, err := net.SplitHostPort(real.Listener.Addr().String())
	if err != nil {
		t.Fatalf("read the address: %v", err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:"+realPort+"/chat", http.StatusTemporaryRedirect)
	}))
	defer front.Close()

	cfg := Config{
		Endpoint:        front.URL,
		Auth:            Auth{Type: AuthNone},
		RequestMapping:  Mapping{MessageField: "message"},
		ResponseMapping: Mapping{MessageField: "response"},
	}
	out, err := NewREST(cfg, PrivateTargetClient(5*time.Second)).Send(context.Background(), "ping")
	if err != nil || out != "pong" {
		t.Fatalf("a redirect within the same host was refused: %q %v", out, err)
	}
}

func TestTheWebSocketDialerIsPinnedByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("pong"))
	}))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	// The WS connector now reports a transport failure as an ERROR. It used to return it as text, and
	// that is what this comment used to describe: the refusal arrived dressed as the target's own
	// words, so the attempt carried no engine.Attempt.Error and a ws:// endpoint that was never
	// reached counted as a technique the target executed.
	out, err := NewWebSocket(url, Auth{Type: AuthNone}, 2*time.Second).Send(context.Background(), "ping")
	if err == nil {
		t.Fatalf("the default WS dialer reached loopback and called it an answer: %q", out)
	}
	if out != "" {
		t.Errorf("a refused dial must return no answer, got %q", out)
	}
	if !strings.Contains(err.Error(), "Private/internal") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}

	if out, err := NewWebSocket(url, Auth{Type: AuthNone}, 2*time.Second, loopbackWSDialer()).
		Send(context.Background(), "ping"); err != nil || out != "pong" {
		t.Fatalf("the opt-out dialer should still reach a private target: %q %v", out, err)
	}
}
