package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testBaseURL = "https://fly-mcp.example"

func TestOAuthFlowRenewsAndCallsMachinesDirectly(t *testing.T) {
	t.Parallel()

	const originalCredential = "fo1_fixture-user-login"
	firstPermissions := "FlyV1 " + managementToken(t, "A", 1) + "," + managementToken(t, "B", 2)
	firstManagement := firstPermissions + "," + originalCredential
	var mu sync.Mutex
	var verifiedCredential string
	flyAPI := httptest.NewServer(flyLoginFixture(t, originalCredential, managementFixture(t, originalCredential, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential := r.Header.Get("Authorization")
		if credential != "Bearer "+originalCredential {
			t.Error("did not reuse the exact fo1 credential")
			http.Error(w, "unexpected credential", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		verifiedCredential = credential
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var body struct{ Query string }
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid verification query")
			w.WriteHeader(400)
			return
		}
		if !strings.Contains(body.Query, "query FlyMCPAuthorize") || !strings.Contains(body.Query, "viewer") || strings.Contains(body.Query, "mutation") || strings.Contains(body.Query, "organization") {
			t.Error("unexpected API operation: verify identity without minting or checking organization membership")
		}
		_, _ = io.WriteString(w, `{"data":{"viewer":{"id":"fixture-user"}}}`)
	}))))
	defer flyAPI.Close()

	var machinesAuthorization string
	machinesAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		machinesAuthorization = r.Header.Get("Authorization")
		mu.Unlock()
		if r.Header.Get("Mcp-Session-Id") != "" || r.Header.Get("Last-Event-ID") != "" {
			t.Error("gateway forwarded client session state to Fly")
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/apps/fixture-app/machines" {
			t.Error("wrong Machines API request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"fixture-machine","name":"test","state":"started","region":"iad","config":{"env":{"PRIVATE":"never-return-this"}}}]`)
	}))
	defer machinesAPI.Close()

	handler := testHandler(t, machinesAPI.URL, flyAPI.URL)
	now := time.Unix(1800000000, 0)
	handler.oauth.now = func() time.Time { return now }
	handler.oauth.fly.now = handler.oauth.now
	clientID := registerClient(t, handler, "https://client.example/oauth/callback")
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	authorizeURL := "/authorize?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.example/oauth/callback"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"mcp offline_access"},
		"resource":              {testBaseURL + "/mcp"},
		"state":                 {"client-state"},
	}.Encode()
	authorize := performRequest(handler, http.MethodGet, authorizeURL, "", "")
	if authorize.Code != http.StatusOK {
		t.Fatalf("authorize status = %d, body = %s", authorize.Code, authorize.Body.String())
	}
	if got := authorize.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("authorization page CSP = %q", got)
	}
	if !strings.Contains(authorize.Body.String(), `id="completion_code"`) || strings.Contains(authorize.Body.String(), `name="consent"`) {
		t.Fatal("authorization did not start Fly login directly")
	}
	cookie := authorize.Result().Cookies()[0]
	finishForm := url.Values{"request": {authorizationForm(t, authorize)}, "completion_code": {"fixture-completion"}}
	if response := postLogin(handler, nil, finishForm); response.Code != http.StatusBadRequest {
		t.Fatal("login accepted without browser binding")
	}
	if response := postLogin(handler, cookie, url.Values{"request": finishForm["request"]}); response.Code != http.StatusBadRequest {
		t.Fatal("login accepted without a completion code")
	}
	finish := postLogin(handler, cookie, finishForm)
	if finish.Code != http.StatusFound {
		t.Fatalf("finish authorization status = %d, body = %s", finish.Code, finish.Body.String())
	}
	if response := postLogin(handler, cookie, finishForm); response.Code != http.StatusBadRequest {
		t.Fatal("Fly redemption replay accepted")
	}
	redirect, err := url.Parse(finish.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Host != "client.example" || redirect.Query().Get("state") != "client-state" || redirect.Query().Get("iss") != testBaseURL {
		t.Fatalf("unexpected authorization redirect: %s", redirect)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("authorization redirect omitted code")
	}
	if len(code) > 64 || strings.HasPrefix(code, sealedTokenPrefix) {
		t.Fatalf("authorization callback carries the credential bundle: code length %d", len(code))
	}
	grantID := "code:" + hashClientID(code)
	pending := handler.oauth.lookupGrant(grantID)
	var stored authorizationCode
	if handler.oauth.sealer.open(pending.sealedCode, "authorization_code", &stored) != nil || stored.Management == nil || stored.Management.Token != firstManagement || stored.FlyToken != originalCredential {
		t.Fatal("pending code did not retain the encrypted completed grant")
	}
	restarted := testHandler(t, machinesAPI.URL, flyAPI.URL)
	if response := exchangeCode(restarted, clientID, code, verifier); response.Code != http.StatusBadRequest {
		t.Fatal("restart accepted an unspent code without its encrypted grant")
	}
	expired := testHandler(t, machinesAPI.URL, flyAPI.URL)
	expired.oauth.now = handler.oauth.now
	expired.oauth.rememberGrant(grantID, pending)
	expired.oauth.now = func() time.Time { return now.Add(codeTTL) }
	if response := exchangeCode(expired, clientID, code, verifier); response.Code != http.StatusBadRequest {
		t.Fatal("authorization code accepted at its deadline")
	}
	if len(expired.oauth.pendingGrants) != 0 {
		t.Fatal("expired authorization payload retained after lookup")
	}
	if response := exchangeCode(handler, "another-client", code, verifier); response.Code != http.StatusBadRequest {
		t.Fatal("authorization code accepted for another client")
	}

	wrongVerifier := exchangeCode(handler, clientID, code, strings.Repeat("x", 64))
	if wrongVerifier.Code != http.StatusBadRequest || !strings.Contains(wrongVerifier.Body.String(), "PKCE verification failed") {
		t.Fatalf("wrong verifier response = %d %s", wrongVerifier.Code, wrongVerifier.Body.String())
	}
	codeResults := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { codeResults <- exchangeCode(handler, clientID, code, verifier) }()
	}
	var exchange *httptest.ResponseRecorder
	for range 2 {
		response := <-codeResults
		if response.Code == http.StatusOK {
			if exchange != nil {
				t.Fatal("concurrent authorization-code exchange succeeded twice")
			}
			exchange = response
		} else if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_grant") {
			t.Fatalf("code exchange status = %d, body = %s", response.Code, response.Body.String())
		}
	}
	if exchange == nil {
		t.Fatal("no code exchange succeeded after invalid client and verifier attempts")
	}
	if handler.oauth.lookupGrant(grantID).sealedCode != "" {
		t.Fatal("consumed authorization payload was retained")
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(exchange.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.ExpiresIn != 540 {
		t.Fatalf("unexpected token response: %+v", tokens)
	}
	if strings.Contains(tokens.AccessToken, originalCredential) || strings.Contains(tokens.RefreshToken, originalCredential) {
		t.Fatal("OAuth response exposed the Fly credential in plaintext")
	}
	var claims bearerClaims
	if err := handler.oauth.sealer.open(tokens.AccessToken, "access_token", &claims); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(claims.Subject, "fly:") || claims.FlyToken != firstManagement {
		t.Fatal("access must carry management permissions for both organization pages")
	}
	var refreshClaims bearerClaims
	if handler.oauth.sealer.open(tokens.RefreshToken, refreshPurpose, &refreshClaims) != nil || refreshClaims.FlyToken != originalCredential || refreshClaims.ExpiresAt != now.Add(30*24*time.Hour).Unix() {
		t.Fatal("refresh must retain only fo1 and the original connection deadline")
	}

	replay := exchangeCode(handler, clientID, code, verifier)
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "invalid_grant") {
		t.Fatalf("code replay response = %d %s", replay.Code, replay.Body.String())
	}

	mcpRequest := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fly-machine-list","arguments":{"app":"fixture-app"}}}`))
	mcpRequest.Header.Set("Content-Type", "application/json")
	mcpRequest.Header.Set("Accept", "application/json, text/event-stream")
	mcpRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	mcpRequest.Header.Set("Mcp-Session-Id", "another-users-session")
	mcpRequest.Header.Set("Last-Event-ID", "another-users-event")
	mcp := performRecorderRequest(handler, mcpRequest)
	if mcp.Code != http.StatusOK || !strings.Contains(mcp.Body.String(), "fixture-machine") || strings.Contains(mcp.Body.String(), "never-return-this") {
		t.Fatalf("MCP response = %d %s", mcp.Code, mcp.Body.String())
	}
	if mcp.Header().Get("Mcp-Session-Id") != "" {
		t.Fatal("gateway exposed a shared session")
	}

	mu.Lock()
	verified := verifiedCredential
	machinesAuth := machinesAuthorization
	mu.Unlock()
	if verified != "Bearer "+originalCredential || machinesAuth != firstPermissions {
		t.Fatal("Machines did not receive only management credentials")
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {clientID},
		"resource":      {testBaseURL + "/mcp"},
	}
	refreshForm.Set("client_id", "wrong-client")
	wrongClient := performRequest(handler, http.MethodPost, "/token", refreshForm.Encode(), "application/x-www-form-urlencoded")
	if wrongClient.Code != http.StatusBadRequest {
		t.Fatal("refresh accepted for another client")
	}
	refreshForm.Set("client_id", clientID)
	now = now.Add(9 * time.Minute)
	if _, err := handler.oauth.verifyBearer("Bearer " + tokens.AccessToken); err == nil {
		t.Fatal("access accepted at the management refresh deadline")
	}
	firstRefresh := performRequest(handler, http.MethodPost, "/token", refreshForm.Encode(), "application/x-www-form-urlencoded")
	if firstRefresh.Code != http.StatusOK || json.Unmarshal(firstRefresh.Body.Bytes(), &tokens) != nil {
		t.Fatal("valid refresh failed")
	}
	refreshForm.Set("refresh_token", tokens.RefreshToken)
	if _, err := handler.oauth.verifyBearer("Bearer " + tokens.AccessToken); err != nil {
		t.Fatal("refreshed access token is not usable")
	}
	if handler.oauth.sealer.open(tokens.AccessToken, "access_token", &claims) != nil || claims.FlyToken != "FlyV1 "+managementToken(t, "A", 3)+","+managementToken(t, "B", 4)+","+originalCredential {
		t.Fatal("refresh reused old management permissions")
	}
	if handler.oauth.sealer.open(tokens.RefreshToken, refreshPurpose, &refreshClaims) != nil || refreshClaims.FlyToken != originalCredential || refreshClaims.ExpiresAt != now.Add(30*24*time.Hour-9*time.Minute).Unix() {
		t.Fatal("renewal extended login lifetime or retained management tokens in refresh")
	}
	if response := performRequest(restarted, http.MethodPost, "/token", refreshForm.Encode(), "application/x-www-form-urlencoded"); response.Code != http.StatusBadRequest {
		t.Fatal("restart accepted a refresh token without its replay state")
	}
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			results <- performRequest(handler, http.MethodPost, "/token", refreshForm.Encode(), "application/x-www-form-urlencoded")
		}()
	}
	var rotated string
	successes := 0
	for range 2 {
		refresh := <-results
		if refresh.Code == http.StatusOK {
			successes++
			var result struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(refresh.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			rotated = result.RefreshToken
		} else if refresh.Code != http.StatusBadRequest {
			t.Fatalf("refresh returned %d", refresh.Code)
		}
	}
	if successes != 1 || rotated == "" || rotated == tokens.RefreshToken {
		t.Fatal("concurrent refresh did not consume exactly once and rotate")
	}
	refreshForm.Set("refresh_token", rotated)
	if response := performRequest(handler, http.MethodPost, "/token", refreshForm.Encode(), "application/x-www-form-urlencoded"); response.Code != http.StatusBadRequest {
		t.Fatal("refresh replay did not revoke its successor")
	}
	if _, err := handler.oauth.verifyBearer("Bearer " + tokens.AccessToken); err == nil {
		t.Fatal("refresh replay did not revoke its access tokens")
	}
}

func TestDiscoveryAndBearerChallenge(t *testing.T) {
	t.Parallel()
	flyAPI := httptest.NewServer(http.NotFoundHandler())
	defer flyAPI.Close()
	handler := testHandler(t, flyAPI.URL, flyAPI.URL)

	metadata := performRequest(handler, http.MethodGet, "/.well-known/oauth-authorization-server", "", "")
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), `"code_challenge_methods_supported":["S256"]`) || !strings.Contains(metadata.Body.String(), `"registration_endpoint"`) {
		t.Fatalf("OAuth metadata = %d %s", metadata.Code, metadata.Body.String())
	}
	resource := performRequest(handler, http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", "")
	if resource.Code != http.StatusOK || !strings.Contains(resource.Body.String(), testBaseURL+`/mcp`) {
		t.Fatalf("resource metadata = %d %s", resource.Code, resource.Body.String())
	}
	unauthorized := performRequest(handler, http.MethodPost, "/mcp", `{}`, "application/json")
	if unauthorized.Code != http.StatusUnauthorized || !strings.Contains(unauthorized.Header().Get("WWW-Authenticate"), `resource_metadata="`+testBaseURL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("bearer challenge = %d %q", unauthorized.Code, unauthorized.Header().Get("WWW-Authenticate"))
	}
}

func TestDynamicRegistrationValidatesRedirectURIs(t *testing.T) {
	t.Parallel()
	flyAPI := httptest.NewServer(http.NotFoundHandler())
	defer flyAPI.Close()
	handler := testHandler(t, flyAPI.URL, flyAPI.URL)

	clientID := registerClient(t, handler, "http://127.0.0.1:8976/oauth/callback")
	if !strings.HasPrefix(clientID, sealedTokenPrefix) {
		t.Fatalf("client ID = %q", clientID)
	}

	for _, redirectURI := range []string{
		"http://example.com/callback", "javascript:alert(1)", "https://user@example.com/callback",
		"https://attacker.example/callback", "https://client.example.attacker.example/auth/mcp/callback",
		"https://client.example/oauth/callback?redirect=https://attacker.example",
		"https://client.example/oauth/callback/", "https://client.example/auth/callback",
		"https://client.example/oauth/other",
		"https://client.example/other-path", "http://127.0.0.1:9999/oauth/callback",
	} {
		body := `{"redirect_uris":[` + mustJSON(t, redirectURI) + `]}`
		response := performRequest(handler, http.MethodPost, "/register", body, "application/json")
		if response.Code != http.StatusBadRequest {
			t.Errorf("registration with %q returned %d", redirectURI, response.Code)
		}
	}
}

func TestSealedTokensArePurposeBoundAndAuthenticated(t *testing.T) {
	t.Parallel()
	sealer, err := newSealer(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := sealer.seal("access_token", map[string]string{"secret": "value"})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]string
	if err := sealer.open(token, "access_token", &value); err != nil || value["secret"] != "value" {
		t.Fatalf("open token: value=%v err=%v", value, err)
	}
	if err := sealer.open(token, "refresh_token", &value); err == nil {
		t.Fatal("token opened for the wrong purpose")
	}
	index := len(token) / 2
	replacement := byte('A')
	if token[index] == replacement {
		replacement = 'B'
	}
	tampered := token[:index] + string(replacement) + token[index+1:]
	if err := sealer.open(tampered, "access_token", &value); err == nil {
		t.Fatal("tampered token was accepted")
	}
}

func TestSealedStateFitsOAuthForms(t *testing.T) {
	s, err := newSealer(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	// JSON quotes + a 12-byte nonce + a 16-byte tag, base64url encoded with
	// the five-byte prefix: 18,398 ASCII bytes exactly fill the 24 KiB budget.
	payload := strings.Repeat("x", 18398)
	token, err := s.seal("authorization_request", payload)
	if err != nil || len(token) != 24*1024 {
		t.Fatal("rejected state at the outbound size limit")
	}
	var opened string
	if err := s.open(token, "authorization_request", &opened); err != nil || opened != payload {
		t.Fatal("issued state cannot be read back")
	}
	if token, err := s.seal("authorization_request", payload+"x"); err == nil || token != "" {
		t.Fatal("issued oversized state instead of failing before browser continuation")
	}
}

func testHandler(t *testing.T, machinesURL, flyAPIURL string) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		PublicBaseURL:      testBaseURL,
		FlyMachinesURL:     machinesURL,
		FlyGraphQLURL:      flyAPIURL + "/graphql",
		TokenEncryptionKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CredentialTTL:      30 * 24 * time.Hour,
		AccessTokenTTL:     15 * time.Minute,
		ClientTTL:          24 * time.Hour,
		OAuthRedirectURIs:  []string{"https://client.example/oauth/callback", "http://127.0.0.1:8976/oauth/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func registerClient(t *testing.T, handler http.Handler, redirectURI string) string {
	t.Helper()
	body := `{"redirect_uris":[` + mustJSON(t, redirectURI) + `],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"Example MCP client","client_uri":"https://client.example"}`
	response := performRequest(handler, http.MethodPost, "/register", body, "application/json")
	if response.Code != http.StatusCreated {
		t.Fatalf("registration response = %d %s", response.Code, response.Body.String())
	}
	var registration struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	return registration.ClientID
}

func exchangeCode(handler http.Handler, clientID, code, verifier string) *httptest.ResponseRecorder {
	return performRequest(handler, http.MethodPost, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {"https://client.example/oauth/callback"},
		"code_verifier": {verifier},
		"resource":      {testBaseURL + "/mcp"},
	}.Encode(), "application/x-www-form-urlencoded")
}

func performRequest(handler http.Handler, method, target, body, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func performRecorderRequest(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
