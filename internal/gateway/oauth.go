package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	mcpScope       = "mcp"
	offlineScope   = "offline_access"
	maxOAuthBody   = 32 * 1024
	codeTTL        = 5 * time.Minute
	refreshPurpose = "refresh_token"
)

type clientClaims struct {
	RedirectURIs []string `json:"redirect_uris"`
	IssuedAt     int64    `json:"iat"`
	ExpiresAt    int64    `json:"exp"`
}

type authorizationRequest struct {
	ClientHash     string              `json:"client_hash"`
	RedirectURI    string              `json:"redirect_uri"`
	State          string              `json:"state,omitempty"`
	CodeChallenge  string              `json:"code_challenge"`
	Scope          string              `json:"scope"`
	Resource       string              `json:"resource"`
	ExpiresAt      int64               `json:"exp"`
	ID             string              `json:"jti"`
	BrowserHash    string              `json:"browser_hash"`
	FlySessionID   string              `json:"fly_session_id,omitempty"`
	FlyVerifier    string              `json:"fly_verifier,omitempty"`
	FlyApprovalURL string              `json:"fly_approval_url,omitempty"`
	Credential     *preparedCredential `json:"credential,omitempty"`
	Management     *managementGrant    `json:"management,omitempty"`
}

type authorizationCode struct {
	ClientHash    string           `json:"client_hash"`
	RedirectURI   string           `json:"redirect_uri"`
	CodeChallenge string           `json:"code_challenge"`
	Scope         string           `json:"scope"`
	Resource      string           `json:"resource"`
	FlyToken      string           `json:"fly_token"`
	Subject       string           `json:"sub"`
	CredentialExp int64            `json:"credential_exp"`
	ExpiresAt     int64            `json:"exp"`
	Management    *managementGrant `json:"management"`
}

type pendingGrant struct {
	expiresAt  int64
	sealedCode string // Only authorization-code grants retain encrypted payloads.
}

type bearerClaims struct {
	ClientHash    string `json:"client_hash"`
	FamilyID      string `json:"family_id"`
	Scope         string `json:"scope"`
	Resource      string `json:"resource"`
	FlyToken      string `json:"fly_token"`
	Subject       string `json:"sub"`
	CredentialExp int64  `json:"credential_exp"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

type oauthHandlers struct {
	baseURL       string
	resourceURL   string
	redirectURIs  []string
	sealer        *sealer
	fly           *flyClient
	now           func() time.Time
	accessTTL     time.Duration
	clientTTL     time.Duration
	grantMu       sync.Mutex
	pendingGrants map[string]pendingGrant
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
}

func (o *oauthHandlers) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, "GET, OPTIONS")
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         o.baseURL,
		"authorization_endpoint":                         o.baseURL + "/authorize",
		"token_endpoint":                                 o.baseURL + "/token",
		"registration_endpoint":                          o.baseURL + "/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               []string{mcpScope, offlineScope},
	})
}

func (o *oauthHandlers) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, "GET, OPTIONS")
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 o.resourceURL,
		"authorization_servers":    []string{o.baseURL},
		"scopes_supported":         []string{mcpScope},
		"bearer_methods_supported": []string{"header"},
	})
}

func (o *oauthHandlers) register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, "POST, OPTIONS")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var registration registrationRequest
	if err := decodeJSONBody(w, r, &registration); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	if len(registration.RedirectURIs) == 0 || len(registration.RedirectURIs) > 10 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "provide between one and ten redirect URIs")
		return
	}
	for _, redirectURI := range registration.RedirectURIs {
		if !slices.Contains(o.redirectURIs, redirectURI) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "callback is not an approved redirect URI")
			return
		}
	}
	if registration.TokenEndpointAuthMethod != "" && registration.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public PKCE clients are supported")
		return
	}
	if !onlyContains(registration.GrantTypes, "authorization_code", "refresh_token") || !onlyContains(registration.ResponseTypes, "code") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant or response type")
		return
	}

	now := o.now().UTC()
	clientID, err := o.sealer.seal("client", clientClaims{
		RedirectURIs: registration.RedirectURIs,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(o.clientTTL).Unix(),
	})
	if err != nil {
		http.Error(w, "could not register client", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        now.Unix(),
		"redirect_uris":              registration.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                registration.ClientName,
	})
}

func (o *oauthHandlers) authorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		o.beginAuthorization(w, r)
	case http.MethodPost:
		o.finishAuthorization(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (o *oauthHandlers) beginAuthorization(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get("client_id")
	var client clientClaims
	if o.sealer.open(clientID, "client", &client) != nil || client.ExpiresAt <= o.now().Unix() {
		writeAuthorizationError(w, "invalid_client", "unknown or expired OAuth client")
		return
	}
	redirectURI := query.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) || !slices.Contains(o.redirectURIs, redirectURI) {
		writeAuthorizationError(w, "invalid_request", "redirect_uri is not registered")
		return
	}
	if query.Get("response_type") != "code" {
		o.redirectAuthorizationError(w, r, redirectURI, query.Get("state"), "unsupported_response_type", "response_type must be code")
		return
	}
	challenge := query.Get("code_challenge")
	if query.Get("code_challenge_method") != "S256" || !validCodeChallenge(challenge) {
		o.redirectAuthorizationError(w, r, redirectURI, query.Get("state"), "invalid_request", "PKCE with S256 is required")
		return
	}
	scope, err := normalizeScope(query.Get("scope"))
	if err != nil {
		o.redirectAuthorizationError(w, r, redirectURI, query.Get("state"), "invalid_scope", err.Error())
		return
	}
	resource := query.Get("resource")
	if resource == "" {
		resource = o.resourceURL
	}
	if resource != o.resourceURL {
		o.redirectAuthorizationError(w, r, redirectURI, query.Get("state"), "invalid_target", "resource does not identify this MCP server")
		return
	}

	browser, err := randomID()
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	id, err := randomID()
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	expires := o.now().Add(15 * time.Minute).Unix()
	ctx, cancel := contextWithTimeout(r, 45*time.Second)
	defer cancel()
	sessionID, verifier, approvalURL, err := o.fly.startLogin(ctx)
	if err != nil {
		o.renderAuthorizationPage(w, http.StatusBadRequest, "", "Could not start Fly login. Return to your MCP client and reconnect. "+err.Error())
		return
	}
	requestToken, err := o.sealer.seal("authorization_request", authorizationRequest{
		ClientHash:    hashClientID(clientID),
		RedirectURI:   redirectURI,
		State:         query.Get("state"),
		CodeChallenge: challenge,
		Scope:         scope,
		Resource:      resource,
		ExpiresAt:     expires,
		ID:            id, BrowserHash: hashClientID(browser),
		FlySessionID: sessionID, FlyVerifier: verifier, FlyApprovalURL: approvalURL,
	})
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	o.rememberGrant("login:"+id, pendingGrant{expiresAt: expires})
	http.SetCookie(w, &http.Cookie{Name: "fly_mcp_login", Value: browser, Path: "/authorize", HttpOnly: true, Secure: strings.HasPrefix(o.baseURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 900})
	o.renderAuthorizationPage(w, http.StatusOK, requestToken, "")
}

func (o *oauthHandlers) finishAuthorization(w http.ResponseWriter, r *http.Request) {
	slog.Info("fly_auth", "stage", "authorization_post")
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	requestToken := r.PostForm.Get("request")
	var request authorizationRequest
	if o.sealer.open(requestToken, "authorization_request", &request) != nil || request.ExpiresAt <= o.now().Unix() || !slices.Contains(o.redirectURIs, request.RedirectURI) {
		writeAuthorizationError(w, "invalid_request", "authorization request expired; return to your MCP client and try again")
		return
	}
	cookie, err := r.Cookie("fly_mcp_login")
	if err != nil || hashClientID(cookie.Value) != request.BrowserHash || r.Header.Get("Origin") != o.baseURL {
		slog.Info("fly_auth", "stage", "browser_binding", "accepted", false, "cookie_present", err == nil, "origin_match", r.Header.Get("Origin") == o.baseURL)
		writeAuthorizationError(w, "invalid_request", "authorization must be completed in the browser that started it")
		return
	}
	completionCode := strings.TrimSpace(r.PostForm.Get("completion_code"))
	if request.Management == nil && (completionCode == "" || len(completionCode) > 1024) {
		o.renderAuthorizationPage(w, http.StatusBadRequest, requestToken, "Enter the one-time completion code from Fly, not an API token.")
		return
	}
	if !o.consumeGrant("login:" + request.ID) {
		writeAuthorizationError(w, "invalid_request", "this login step was already used or the service restarted; reconnect your MCP client")
		return
	}

	ctx, cancel := contextWithTimeout(r, 45*time.Second)
	defer cancel()
	var credential preparedCredential
	if request.Management == nil {
		credential, err = o.fly.completeLogin(ctx, request.FlySessionID, request.FlyVerifier, completionCode)
		slog.Info("fly_auth", "stage", "login_complete", "accepted", err == nil)
		if err == nil {
			var token string
			var expires time.Time
			token, expires, err = o.fly.managementCredential(ctx, credential.Token)
			if err == nil {
				request.Management = &managementGrant{Token: token, ExpiresAt: expires.Unix()}
			}
		}
	} else if request.Credential != nil {
		credential = *request.Credential
		err = o.fly.completeManagement(ctx, request.Management)
	} else {
		err = errors.New("Invalid Fly management continuation; reconnect your MCP client")
	}
	var pending *managementPending
	if errors.As(err, &pending) {
		request.Credential = &credential
		request.Management = &pending.Grant
		request.ExpiresAt = min(request.ExpiresAt, pending.Grant.ExpiresAt)
		request.FlySessionID, request.FlyVerifier, request.FlyApprovalURL = "", "", ""
		request.ID, err = randomID()
		var next string
		if err == nil {
			next, err = o.sealer.seal("authorization_request", request)
		}
		if err != nil {
			http.Error(w, "could not continue authorization", http.StatusInternalServerError)
			return
		}
		o.rememberGrant("login:"+request.ID, pendingGrant{expiresAt: request.ExpiresAt})
		o.renderAuthorizationPage(w, http.StatusOK, next, "")
		return
	}
	if err != nil {
		o.renderAuthorizationPage(w, http.StatusBadRequest, "", err.Error()+"\nReturn to your MCP client and reconnect to try again.")
		return
	}

	id, err := randomID()
	if err != nil {
		http.Error(w, "could not complete authorization", http.StatusInternalServerError)
		return
	}
	expires := min(o.now().Add(codeTTL).Unix(), request.Management.ExpiresAt)
	code, err := o.sealer.seal("authorization_code", authorizationCode{
		ClientHash:    request.ClientHash,
		RedirectURI:   request.RedirectURI,
		CodeChallenge: request.CodeChallenge,
		Scope:         request.Scope,
		Resource:      request.Resource,
		FlyToken:      credential.Token,
		Subject:       credential.Subject,
		CredentialExp: credential.ExpiresAt.Unix(),
		ExpiresAt:     expires,
		Management:    request.Management,
	})
	if err != nil {
		http.Error(w, "could not complete authorization", http.StatusInternalServerError)
		return
	}

	// Keep credential-sized ciphertext off browser/app callback URLs. The opaque
	// handle has 144 random bits; its encrypted payload expires with the code.
	o.rememberGrant("code:"+hashClientID(id), pendingGrant{expiresAt: expires, sealedCode: code})
	redirect, _ := url.Parse(request.RedirectURI)
	values := redirect.Query()
	values.Set("code", id)
	if request.State != "" {
		values.Set("state", request.State)
	}
	values.Set("iss", o.baseURL)
	redirect.RawQuery = values.Encode()
	w.Header().Set("Cache-Control", "no-store")
	slog.Info("fly_auth", "stage", "authorization_redirect", "code_length", len(id), "state_present", request.State != "")
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (o *oauthHandlers) token(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, "POST, OPTIONS")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if r.Header.Get("Authorization") != "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "this server accepts public PKCE clients")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		o.exchangeAuthorizationCode(w, r)
	case "refresh_token":
		o.exchangeRefreshToken(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func (o *oauthHandlers) exchangeAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	slog.Info("fly_auth", "stage", "oauth_code_exchange")
	grantID := "code:" + hashClientID(r.Form.Get("code"))
	grant := o.lookupGrant(grantID)
	var code authorizationCode
	if o.sealer.open(grant.sealedCode, "authorization_code", &code) != nil || code.Management == nil || code.ExpiresAt <= o.now().Unix() || code.CredentialExp <= o.now().Unix() || !slices.Contains(o.redirectURIs, code.RedirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if hashClientID(r.Form.Get("client_id")) != code.ClientHash || r.Form.Get("redirect_uri") != code.RedirectURI || !resourceMatches(r.Form.Get("resource"), code.Resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code does not belong to this client")
		return
	}
	verifier := r.Form.Get("code_verifier")
	if !validCodeVerifier(verifier) || !pkceMatches(verifier, code.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if !o.consumeGrant(grantID) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was already used")
		return
	}
	o.issueTokens(r.Context(), w, code.ClientHash, code.Scope, code.Resource, code.FlyToken, code.Subject, code.CredentialExp, "", code.Management)
}

func (o *oauthHandlers) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	var refresh bearerClaims
	if o.sealer.open(r.Form.Get("refresh_token"), refreshPurpose, &refresh) != nil || refresh.ExpiresAt <= o.now().Unix() || refresh.CredentialExp <= o.now().Unix() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	if hashClientID(r.Form.Get("client_id")) != refresh.ClientHash || !resourceMatches(r.Form.Get("resource"), refresh.Resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token does not belong to this client")
		return
	}
	if !o.grantValid("family:"+refresh.FamilyID) || !o.consumeGrant("refresh:"+hashClientID(r.Form.Get("refresh_token"))) {
		// A replay may be a stolen token. Revoke its successors as well.
		o.consumeGrant("family:" + refresh.FamilyID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was already used or the gateway restarted; reconnect your MCP client")
		return
	}
	o.issueTokens(r.Context(), w, refresh.ClientHash, refresh.Scope, refresh.Resource, refresh.FlyToken, refresh.Subject, refresh.CredentialExp, refresh.FamilyID, nil)
}

func (o *oauthHandlers) issueTokens(ctx context.Context, w http.ResponseWriter, clientHash, scope, resource, flyToken, subject string, credentialExp int64, familyID string, prepared *managementGrant) {
	var management string
	var managementExp time.Time
	var err error
	if prepared == nil {
		management, managementExp, err = o.fly.managementCredential(ctx, flyToken)
	} else {
		err = o.fly.completeManagement(ctx, prepared)
		management, managementExp = prepared.Token, time.Unix(prepared.ExpiresAt, 0)
	}
	if err != nil {
		o.consumeGrant("family:" + familyID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Could not obtain Fly management access; reconnect your MCP client. "+err.Error())
		return
	}
	now := o.now().UTC()
	accessExp := min(now.Add(o.accessTTL).Unix(), credentialExp, managementExp.Unix())
	if accessExp <= now.Unix() {
		o.consumeGrant("family:" + familyID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Fly connection expired during token exchange; reconnect your MCP client")
		return
	}
	if familyID == "" {
		var err error
		familyID, err = randomID()
		if err != nil {
			http.Error(w, "could not issue tokens", http.StatusInternalServerError)
			return
		}
		o.rememberGrant("family:"+familyID, pendingGrant{expiresAt: credentialExp})
	}
	claims := bearerClaims{
		ClientHash: clientHash, Scope: scope, Resource: resource, FlyToken: management,
		Subject: subject, CredentialExp: credentialExp, IssuedAt: now.Unix(), ExpiresAt: accessExp, FamilyID: familyID,
	}
	accessToken, err := o.sealer.seal("access_token", claims)
	if err != nil {
		http.Error(w, "could not issue tokens", http.StatusInternalServerError)
		return
	}
	// Refresh retains only the login credential, never stale management tokens.
	claims.FlyToken = flyToken
	claims.ExpiresAt = credentialExp
	refreshToken, err := o.sealer.seal(refreshPurpose, claims)
	if err != nil {
		http.Error(w, "could not issue tokens", http.StatusInternalServerError)
		return
	}

	o.rememberGrant("refresh:"+hashClientID(refreshToken), pendingGrant{expiresAt: credentialExp})
	slog.Info("fly_auth", "stage", "oauth_tokens_issued")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    accessExp - now.Unix(),
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

func (o *oauthHandlers) verifyBearer(authorization string) (bearerClaims, error) {
	scheme, token, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return bearerClaims{}, errors.New("missing bearer token")
	}
	var claims bearerClaims
	if o.sealer.open(strings.TrimSpace(token), "access_token", &claims) != nil || claims.ExpiresAt <= o.now().Unix() || claims.CredentialExp <= o.now().Unix() || claims.Resource != o.resourceURL || !slices.Contains(strings.Fields(claims.Scope), mcpScope) {
		return bearerClaims{}, errors.New("invalid bearer token")
	}
	if !o.grantValid("family:" + claims.FamilyID) {
		return bearerClaims{}, errors.New("revoked bearer token")
	}
	return claims, nil
}

// Authorization grants also retain encrypted payloads, never plaintext credentials.
// Restarting fails closed: no old code or refresh token can be consumed again.
func (o *oauthHandlers) rememberGrant(id string, grant pendingGrant) {
	o.grantMu.Lock()
	defer o.grantMu.Unlock()
	now := o.now().Unix()
	for grantID, existing := range o.pendingGrants {
		if existing.expiresAt <= now {
			delete(o.pendingGrants, grantID)
		}
	}
	o.pendingGrants[id] = grant
}

func (o *oauthHandlers) consumeGrant(id string) bool {
	o.grantMu.Lock()
	defer o.grantMu.Unlock()
	grant, exists := o.pendingGrants[id]
	delete(o.pendingGrants, id)
	return exists && grant.expiresAt > o.now().Unix()
}

func (o *oauthHandlers) lookupGrant(id string) pendingGrant {
	o.grantMu.Lock()
	defer o.grantMu.Unlock()
	grant := o.pendingGrants[id]
	if grant.expiresAt <= o.now().Unix() {
		delete(o.pendingGrants, id)
		return pendingGrant{}
	}
	return grant
}

func (o *oauthHandlers) grantValid(id string) bool {
	return o.lookupGrant(id).expiresAt > o.now().Unix()
}

func (o *oauthHandlers) redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirect, _ := url.Parse(redirectURI)
	values := redirect.Query()
	values.Set("error", code)
	values.Set("error_description", description)
	if state != "" {
		values.Set("state", state)
	}
	redirect.RawQuery = values.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

var authorizationPage = template.Must(template.New("authorization").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect Fly.io</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; padding: 2rem 1rem; background: #f5f5f4; color: #1c1917; }
    main { max-width: 34rem; margin: 4vh auto; padding: 2rem; border: 1px solid #d6d3d1; border-radius: .75rem; background: white; box-shadow: 0 1px 3px #0001; }
    h1 { margin-top: 0; font-size: 1.5rem; }
    label { display: block; margin: 1.5rem 0 .5rem; font-weight: 650; }
    input { box-sizing: border-box; width: 100%; padding: .75rem; border: 1px solid #a8a29e; border-radius: .4rem; font: inherit; }
    button { margin-top: 1rem; padding: .7rem 1rem; border: 0; border-radius: .4rem; background: #14b8a6; color: #042f2e; font: inherit; font-weight: 700; cursor: pointer; }
    .error { padding: .75rem; border-radius: .4rem; background: #fee2e2; color: #991b1b; white-space: pre-wrap; overflow-wrap: anywhere; }
    .small { color: #57534e; font-size: .9rem; line-height: 1.45; }
    @media (prefers-color-scheme: dark) { body { background: #0c0a09; color: #fafaf9; } main { background: #1c1917; border-color: #44403c; } .small { color: #d6d3d1; } }
  </style>
</head>
<body><main>
  <h1>Connect Fly.io</h1>
  {{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
  {{if .Request}}
  <form method="post" action="/authorize" autocomplete="off">
    <input type="hidden" name="request" value="{{.Request}}">
    {{if .ManagementPending}}
    <h2>Complete required Fly approval</h2>
    {{if .ManagementApprovalURL}}
    <p><a href="{{.ManagementApprovalURL}}" target="_blank" rel="noopener noreferrer">Open required Fly approval ↗</a></p>
    <p class="small">Fly requires an additional approval for management access. Complete it in the new tab, then return here and check approval. Your MCP client is not connected yet.</p>
    {{else}}
    <p class="small">Fly is still preparing management access. Check again shortly. Your MCP client is not connected yet.</p>
    {{end}}
    <button type="submit">Check approval</button>
    {{else if .ApprovalURL}}
    <p><a href="{{.ApprovalURL}}" target="_blank" rel="noopener noreferrer">Open Fly approval ↗</a></p>
    <p class="small">Approve the session named <strong>Fly MCP gateway</strong>, then return here with its completion code. If Fly does not offer a code, stop; do not paste an API token.</p>
    <label for="completion_code">One-time completion code from Fly</label>
    <input id="completion_code" name="completion_code" type="password" required maxlength="1024" autofocus spellcheck="false" autocomplete="off">
    <button type="submit">Connect</button>
    {{end}}
  </form>
  {{end}}
</main></body></html>`))

func (o *oauthHandlers) renderAuthorizationPage(w http.ResponseWriter, status int, requestToken, message string) {
	formOrigins := []string{"'self'"}
	for _, redirectURI := range o.redirectURIs {
		redirect, err := url.Parse(redirectURI)
		if err == nil {
			formOrigins = append(formOrigins, redirect.Scheme+"://"+redirect.Host)
		}
	}
	// Chromium applies form-action to the POST's cross-origin redirect too.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+strings.Join(formOrigins, " ")+"; base-uri 'none'; frame-ancestors 'none'")
	// Preserve Origin for same-origin form POSTs, without leaking referrers to Fly or the client.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	var request authorizationRequest
	_ = o.sealer.open(requestToken, "authorization_request", &request)
	var approvalURL string
	if request.Management != nil && request.Management.Approval != nil {
		approvalURL = request.Management.Approval.UserURL
	}
	_ = authorizationPage.Execute(w, map[string]any{"Request": requestToken, "Error": message, "ApprovalURL": request.FlyApprovalURL,
		"ManagementPending": request.Management != nil, "ManagementApprovalURL": approvalURL})
}

func validRedirectURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))
}

func validCodeChallenge(value string) bool {
	return len(value) == 43 && isBase64URL(value)
}

func validCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._~", char)) {
			return false
		}
	}
	return true
}

func isBase64URL(value string) bool {
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func pkceMatches(verifier, challenge string) bool {
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(challenge)) == 1
}

func normalizeScope(raw string) (string, error) {
	scopes := strings.Fields(raw)
	if len(scopes) == 0 {
		return mcpScope, nil
	}
	seenMCP := false
	for _, scope := range scopes {
		switch scope {
		case mcpScope:
			seenMCP = true
		case offlineScope:
		default:
			return "", fmt.Errorf("unsupported scope %q", scope)
		}
	}
	if !seenMCP {
		scopes = append(scopes, mcpScope)
	}
	slices.Sort(scopes)
	return strings.Join(slices.Compact(scopes), " "), nil
}

func hashClientID(clientID string) string {
	digest := sha256.Sum256([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func randomID() (string, error) {
	id := make([]byte, 18)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(id), nil
}

func resourceMatches(requested, expected string) bool {
	return requested == "" || requested == expected
}

func onlyContains(values []string, allowed ...string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON client metadata")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	slog.Info("fly_auth", "stage", "oauth_error", "status", status, "code", code)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeAuthorizationError(w http.ResponseWriter, code, description string) {
	slog.Info("fly_auth", "stage", "authorization_error", "code", code)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, "%s: %s\n", code, description)
}
