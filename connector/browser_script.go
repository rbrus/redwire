package connector

import (
	"encoding/json"
	"fmt"
)

// chatScript builds the one expression that drives a full exchange in the page: clear any consent
// banner, open a collapsed widget, type the payload, submit it, and wait for the bot to finish
// answering.
//
// ONE round trip per payload, on purpose. The obvious shape is a CDP call per step — query the input,
// dispatch keys, poll for bubbles — and it is wrong here for a reason that is about evidence rather
// than speed: every extra round trip is another place a scan can fail halfway and leave an attempt
// recorded as delivered-but-unanswered. Composing the whole exchange in the page means the result is
// either a reply or a named error, which is the only shape the judge can read honestly.
//
// The payload crosses into JavaScript as a JSON literal produced by encoding/json, never by string
// concatenation. This connector's entire input is adversarial by construction — the payloads are
// jailbreaks, quote-stuffing and terminator sequences — so building the script by pasting them
// together would be a self-inflicted injection in a tool whose job is finding them.
func (b *Browser) chatScript(message string) (string, error) {
	args, err := json.Marshal(map[string]any{
		"message":  message,
		"input":    b.cfg.InputSelector,
		"send":     b.cfg.SendSelector,
		"response": b.cfg.ResponseSelector,
		"open":     b.cfg.OpenSelector,
		"dismiss":  b.cfg.DismissSelectors,
		"timeout":  b.cfg.ResponseTimeout.Milliseconds(),
		"settle":   b.cfg.SettleMS,
		"opened":   b.sent,
	})
	if err != nil {
		return "", fmt.Errorf("browser: cannot encode the payload for the page: %w", err)
	}
	return "(" + browserChatJS + ")(" + string(args) + ")", nil
}

// browserChatJS is the page-side half of the connector.
//
// Auto-detection is a documented heuristic and the code says where it stops. When it cannot find an
// input it returns an ERROR naming what it looked for — it never returns an empty reply, because a
// widget nobody could type into and a bot that refused to answer are opposite results and the whole
// acceptance suite exists because those two were once indistinguishable.
//
// Reply capture has two modes. With response_selector set it watches that selector's element count
// and reads the new tail. Without it, it diffs document.body.innerText: snapshot before sending, poll
// after, and return what was appended. The diff is cruder but it works on widgets whose bubbles have
// no stable class, which is most of them, and it degrades to "no reply" rather than to a wrong one.
//
// Streaming is handled by settling rather than by waiting for a completion signal, because no such
// signal is standard: the reply is complete when the text has stopped growing for `settle`
// milliseconds.
const browserChatJS = `async (a) => {
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const norm = s => (s || "").replace(/\s+/g, " ").trim();
  const fail = e => ({ok: false, reply: "", error: e});

  try {
    // One-time page preparation. Guarded by a flag on window rather than by a.opened alone so a
    // reload mid-scan re-runs it.
    if (!a.opened || !window.__redwirePrepared) {
      for (const sel of (a.dismiss || [])) {
        try { const el = document.querySelector(sel); if (el) el.click(); } catch (_) {}
      }
      if (a.open) {
        try { const el = document.querySelector(a.open); if (el) { el.click(); await sleep(500); } } catch (_) {}
      }
      window.__redwirePrepared = true;
    }

    // The input. A named selector is authoritative; otherwise take the first visible candidate, in
    // the order a chat widget is most likely to use.
    const visible = el => {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
    };
    let input = null;
    if (a.input) {
      input = document.querySelector(a.input);
      if (!input) return fail("input_selector " + a.input + " matched nothing on the page");
    } else {
      const candidates = [
        'textarea', '[contenteditable="true"]', '[role="textbox"]',
        'input[type="text"]', 'input[type="search"]', 'input:not([type])',
      ];
      for (const sel of candidates) {
        const el = Array.from(document.querySelectorAll(sel)).find(visible);
        if (el) { input = el; break; }
      }
      if (!input) {
        return fail("no chat input found. Looked for a visible textarea, contenteditable, " +
                    "role=textbox or text input. Set connector.browser.input_selector");
      }
    }

    const bubbles = () => a.response ? Array.from(document.querySelectorAll(a.response)) : [];
    const beforeCount = bubbles().length;
    const beforeText = a.response ? "" : norm(document.body.innerText);

    // Type. React and other controlled inputs ignore a plain value assignment, so the native setter
    // is called and an input event dispatched — without this the widget's own state never sees the
    // text and the send button stays disabled.
    input.focus();
    if (input.isContentEditable) {
      input.textContent = a.message;
    } else {
      const proto = input instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
      setter.call(input, a.message);
    }
    input.dispatchEvent(new Event("input", {bubbles: true}));
    input.dispatchEvent(new Event("change", {bubbles: true}));

    // Submit.
    if (a.send) {
      const btn = document.querySelector(a.send);
      if (!btn) return fail("send_selector " + a.send + " matched nothing on the page");
      btn.click();
    } else {
      for (const type of ["keydown", "keypress", "keyup"]) {
        input.dispatchEvent(new KeyboardEvent(type, {
          key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true,
        }));
      }
      const form = input.closest("form");
      if (form && typeof form.requestSubmit === "function") { try { form.requestSubmit(); } catch (_) {} }
    }

    // Wait for the answer, then for it to stop growing.
    const deadline = Date.now() + a.timeout;
    let last = "", lastChange = 0;
    while (Date.now() < deadline) {
      await sleep(150);
      let now = "";
      if (a.response) {
        const all = bubbles();
        if (all.length > beforeCount) {
          now = norm(all.slice(beforeCount).map(e => e.innerText).join("\n"));
        }
      } else {
        const text = norm(document.body.innerText);
        if (text.length > beforeText.length && text.startsWith(beforeText.slice(0, 64))) {
          now = norm(text.slice(beforeText.length));
        } else if (text !== beforeText) {
          now = norm(text.replace(beforeText, ""));
        }
      }
      // The payload is echoed into the transcript by most widgets; it is not the bot's answer.
      if (now && a.message && now.startsWith(norm(a.message))) {
        now = norm(now.slice(norm(a.message).length));
      }
      if (now !== last) { last = now; lastChange = Date.now(); }
      else if (last && Date.now() - lastChange >= a.settle) { return {ok: true, reply: last, error: ""}; }
    }
    if (last) return {ok: true, reply: last, error: ""};
    return fail("the widget did not answer within " + a.timeout + "ms");
  } catch (e) {
    return fail(String((e && e.message) || e));
  }
}`
