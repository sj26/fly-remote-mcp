package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superfly/macaroon/flyio"
)

// Optional Chromium check for browser-enforced CSP and cross-origin redirects.
// Both Fly verification and the OAuth callback are disposable local fixtures.
func TestOAuthBrowserRedirect(t *testing.T) {
	if os.Getenv("BROWSER_TEST") != "1" {
		t.Skip("set BROWSER_TEST=1 with agent-browser installed")
	}
	var verificationFailure atomic.Bool
	discharges := newDischargeFixture(t, "fo1_browser-fixture", flyio.LocationNewAuthentication)
	resources := discharges.api(t)
	flyAPI := httptest.NewServer(flyLoginFixture(t, "fo1_browser-fixture", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verificationFailure.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "fo1_private-upstream-canary")
			return
		}
		resources.ServeHTTP(w, r)
	})))
	defer flyAPI.Close()
	var handler *Handler
	var clientID string
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") != "browser-test" {
			http.Error(w, "missing authorization code or state", http.StatusBadRequest)
			return
		}
		response := performRequest(handler, http.MethodPost, "/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")},
			"client_id": {clientID}, "redirect_uri": {"http://" + r.Host + "/callback"},
			"code_verifier": {strings.Repeat("v", 64)},
		}.Encode(), "application/x-www-form-urlencoded")
		if response.Code != http.StatusOK {
			t.Error("browser callback could not exchange management credentials")
			http.Error(w, "OAuth exchange failed", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "OAuth callback received")
	}))
	defer callback.Close()
	handler = testHandler(t, flyAPI.URL, flyAPI.URL)
	handler.oauth.fly.httpClient.Transport = discharges.transport(t, flyAPI.URL)
	handler.oauth.redirectURIs = []string{callback.URL + "/callback"}
	server := httptest.NewServer(handler)
	defer server.Close()
	handler.oauth.baseURL = server.URL
	clientID = registerClient(t, handler, callback.URL+"/callback")
	digest := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	authorizeURL := server.URL + "/authorize?" + url.Values{
		"client_id": {clientID}, "redirect_uri": {callback.URL + "/callback"},
		"response_type": {"code"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "state": {"browser-test"},
	}.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	defer func() { _ = exec.Command("agent-browser", "--session", "fly-oauth-test", "close").Run() }()
	browser := func(args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "agent-browser", append([]string{"--session", "fly-oauth-test"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("browser %s failed: %v: %s", args[0], err, output)
		}
		return string(output)
	}
	browser("open", authorizeURL)
	browser("set", "viewport", "1280", "720", "2")
	capture := func(name string) {
		if dir := os.Getenv("BROWSER_ARTIFACT_DIR"); dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			browser("screenshot", filepath.Join(dir, name+".png"), "--full")
		}
	}
	browser("wait", "#completion_code")
	if !strings.Contains(browser("eval", "document.querySelector('input[name=consent]') === null"), "true") || !strings.Contains(browser("get", "text", "body"), "Open Fly approval") {
		t.Fatal("authorization did not skip confirmation and start Fly login")
	}
	capture("initial")
	browser("set", "viewport", "390", "844", "2")
	browser("eval", "new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
	capture("initial-narrow")
	browser("set", "viewport", "1280", "720", "2")
	browser("fill", "#completion_code", "fixture-completion")
	browser("click", "button[type=submit]")
	browser("wait", "--text", "Complete required Fly approval")
	if !strings.Contains(browser("get", "text", "body"), "Your MCP client is not connected yet") || discharges.checks.Load() != 0 {
		t.Fatal("browser connected before required Fly approval")
	}
	capture("management-approval")
	browser("set", "viewport", "390", "844", "2")
	browser("eval", "new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
	capture("management-approval-narrow")
	browser("set", "viewport", "1280", "720", "2")
	previousRequest := strings.TrimSpace(browser("get", "value", "input[name=request]"))
	browser("click", "button[type=submit]")
	browser("wait", "--fn", "document.querySelector('input[name=request]')?.value && document.querySelector('input[name=request]').value !== "+strconv.Quote(previousRequest))
	if !strings.Contains(browser("get", "url"), "/authorize") {
		t.Fatal("pending poll left the browser authorization flow")
	}
	discharges.approved.Store(true)
	browser("click", "button[type=submit]")
	browser("wait", "--text", "OAuth callback received")
	if !strings.Contains(browser("get", "text", "body"), "OAuth callback received") {
		t.Fatal("browser did not reach the approved cross-origin OAuth callback")
	}
	// Render the non-interactive pending variant without contacting any issuer.
	pollState, err := handler.oauth.sealer.seal("authorization_request", authorizationRequest{Management: &managementGrant{Approval: &dischargeApproval{}}})
	if err != nil {
		t.Fatal(err)
	}
	preview := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handler.oauth.renderAuthorizationPage(w, http.StatusOK, pollState, "")
	}))
	defer preview.Close()
	browser("open", preview.URL)
	browser("wait", "--text", "Fly is still preparing management access")
	capture("management-poll-only")
	// A fresh login with a rejected completion code must not redirect to the client.
	browser("open", authorizeURL)
	browser("wait", "#completion_code")
	browser("fill", "#completion_code", "incorrect-fixture-code")
	browser("click", "button[type=submit]")
	browser("wait", "[role=alert]")
	if !strings.Contains(browser("get", "text", "body"), "Fly rejected the request") {
		t.Fatal("missing safe redemption error")
	}
	capture("error")
	// A rejected identity check stops login without exposing Fly's response.
	verificationFailure.Store(true)
	browser("open", authorizeURL)
	browser("wait", "#completion_code")
	browser("fill", "#completion_code", "fixture-completion")
	browser("click", "button[type=submit]")
	browser("wait", "[role=alert]")
	details := browser("get", "text", "[role=alert]")
	if !strings.Contains(details, "HTTP 401") || strings.Contains(details, "fo1_") {
		t.Fatal("missing verification failure or exposed upstream credential")
	}
	if !strings.Contains(browser("eval", "document.querySelector('form') === null"), "true") {
		t.Fatal("failed login retained a continuation form")
	}
	capture("verification-error")
	browser("set", "viewport", "390", "844", "2")
	browser("eval", "new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
	capture("verification-error-narrow")
}
