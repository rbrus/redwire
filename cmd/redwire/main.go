// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rbrus/redwire"
	"github.com/rbrus/redwire/connector"
	"github.com/rbrus/redwire/ssrf"
)

var buildVersion = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return nil
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "redwire %s\n", buildVersion)
		return nil

	case "transports", "list":
		fmt.Fprintln(stdout, "Supported transports:")
		for _, t := range connector.Transports {
			fmt.Fprintf(stdout, "  %-10s %s\n", t.ID, t.Display)
		}
		return nil

	case "send":
		return runSend(args[1:], stdin, stdout)

	case "help", "--help", "-h":
		printUsage(stdout)
		return nil

	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `redwire - reach an AI agent behind any of five transports through one Go interface

Usage:
  redwire <command> [options]

Commands:
  send        Send a payload to a target and print the response
  transports  List supported agent transports
  version     Print redwire version
  help        Show this help message

Send Options:
  -transport       Transport to use (rest, mcp, a2a, ws, browser) [required]
  -endpoint        Target endpoint URL [required]
  -token           Bearer token for authorization
  -api-key-header  Header name for API key authentication
  -api-key-value   Header value for API key authentication
  -allow-private   Allow dials to private/internal addresses (disables SSRF pin)
  -timeout         Request timeout duration (default: 30s)
  -cdp-url         CDP URL for browser transport (default: http://127.0.0.1:9222)
  -req-field       Request message field path for REST (default: message)
  -resp-field      Response message field path for REST (optional)
  -message         Message to send (reads from argument or stdin)

Examples:
  redwire send -transport rest -endpoint https://agent.example/chat -message "Hello agent"
  redwire send -transport mcp -endpoint https://agent.example/mcp -message "Run audit"
  redwire send -transport ws -endpoint wss://agent.example/ws -message "Ping"
  redwire transports
`)
}

func runSend(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)

	transport := fs.String("transport", "", "Target transport: rest, mcp, a2a, ws, browser")
	endpoint := fs.String("endpoint", "", "Target URL or page endpoint")
	token := fs.String("token", "", "Bearer token")
	apiKeyHeader := fs.String("api-key-header", "", "API key header name")
	apiKeyValue := fs.String("api-key-value", "", "API key header value")
	allowPrivate := fs.Bool("allow-private", false, "Allow connecting to private/internal addresses")
	timeout := fs.Duration("timeout", 30*time.Second, "Timeout duration")
	cdpURL := fs.String("cdp-url", "http://127.0.0.1:9222", "Chrome DevTools Protocol URL (browser transport)")
	reqField := fs.String("req-field", "message", "Request message field path for REST")
	respField := fs.String("resp-field", "", "Response message field path for REST")
	messageFlag := fs.String("message", "", "Message payload to send")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *transport == "" {
		return errors.New("-transport flag is required (see 'redwire transports')")
	}
	if *endpoint == "" {
		return errors.New("-endpoint flag is required")
	}

	message := *messageFlag
	if message == "" {
		remaining := fs.Args()
		if len(remaining) > 0 {
			message = strings.Join(remaining, " ")
		} else {
			raw, err := io.ReadAll(stdin)
			if err != nil {
				return fmt.Errorf("read message from stdin: %w", err)
			}
			message = strings.TrimSpace(string(raw))
		}
	}
	if message == "" {
		return errors.New("no message payload provided (via -message, arguments, or stdin)")
	}

	auth := connector.Auth{Type: connector.AuthNone}
	if *token != "" {
		auth = connector.Auth{Type: connector.AuthBearer, Token: *token}
	} else if *apiKeyHeader != "" && *apiKeyValue != "" {
		auth = connector.Auth{
			Type:         connector.AuthAPIKey,
			APIKeyHeader: *apiKeyHeader,
			APIKeyValue:  *apiKeyValue,
		}
	}

	var target redwire.Target

	var client *http.Client
	if *allowPrivate {
		client = connector.PrivateTargetClient(*timeout)
	}

	switch strings.ToLower(*transport) {
	case "rest":
		target = connector.NewREST(connector.Config{
			Endpoint:        *endpoint,
			Auth:            auth,
			RequestMapping:  connector.Mapping{MessageField: *reqField},
			ResponseMapping: connector.Mapping{MessageField: *respField},
			Timeout:         *timeout,
		}, client)

	case "mcp":
		target = connector.NewMCP(*endpoint, auth, client)

	case "a2a":
		target = connector.NewA2A(*endpoint, auth, client)

	case "ws", "websocket":
		var wsDialer = connector.GuardedWSDialer(*timeout)
		if *allowPrivate {
			wsDialer = connector.PrivateTargetWSDialer(*timeout)
		}
		target = connector.NewWebSocket(*endpoint, auth, *timeout, wsDialer)

	case "browser", "webchat":
		target = connector.NewBrowser(connector.BrowserConfig{
			Endpoint:        *endpoint,
			AllowPrivate:    *allowPrivate,
			CDPURL:          *cdpURL,
			ResponseTimeout: *timeout,
		})

	default:
		valid := connector.TransportIDs()
		names := make([]string, 0, len(valid))
		for k := range valid {
			names = append(names, k)
		}
		return fmt.Errorf("unknown transport %q (choose from: %s)", *transport, strings.Join(names, ", "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+5*time.Second)
	defer cancel()

	reply, err := target.Send(ctx, message)
	if err != nil {
		if ssrf.IsSsrfError(err) {
			return fmt.Errorf("SSRF guard refused endpoint: %w (use -allow-private if targeting localhost)", err)
		}
		return err
	}

	fmt.Fprintln(stdout, reply)
	return nil
}
