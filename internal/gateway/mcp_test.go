package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mcpResponse struct {
	Result struct {
		IsError bool `json:"isError"`
		Content []struct{ Text string }
		Tools   []struct {
			Name        string
			Annotations struct{ ReadOnlyHint, DestructiveHint, IdempotentHint bool }
		}
		ServerInfo struct{ Name string }
	}
	Error *struct{ Message string }
}

func mcpRPC(t *testing.T, endpoint, token, method string, params any) mcpResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, endpoint+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Mcp-Session-Id", "untrusted-shared-session")
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result mcpResponse
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatalf("invalid MCP response (HTTP %d)", response.StatusCode)
	}
	if response.Header.Get("Mcp-Session-Id") != "" {
		t.Fatal("MCP response established shared session state")
	}
	return result
}

// The full login and refresh flow is covered in server_test.go. These tokens
// isolate the authenticated tool boundary, without issuing any real credential.
func mcpAccess(t *testing.T, h *Handler, user string) string {
	t.Helper()
	expires := h.oauth.now().Add(time.Minute).Unix()
	h.oauth.rememberGrant("family:"+user, pendingGrant{expiresAt: expires})
	token, err := h.oauth.sealer.seal("access_token", bearerClaims{
		FlyToken: "FlyV1 fm2_" + user + ",fo1_" + user, FamilyID: user,
		Scope: mcpScope, Resource: h.oauth.resourceURL, CredentialExp: expires, ExpiresAt: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestInProcessMCPSurfaceAndIsolation(t *testing.T) {
	// Ambient credentials must never enter an API request.
	t.Setenv("FLY_ACCESS_TOKEN", "ambient-do-not-use")
	t.Setenv("FLY_API_TOKEN", "ambient-do-not-use")
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/v1/apps/") || r.Header.Get("Mcp-Session-Id") != "" {
			t.Error("unexpected API operation or leaked session header")
			w.WriteHeader(400)
			return
		}
		user := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/apps/"), "/machines")
		if r.Header.Get("Authorization") != "FlyV1 fm2_"+user {
			t.Error("request did not use only its caller's management token")
			w.WriteHeader(401)
			return
		}
		_, _ = fmt.Fprintf(w, `[{"id":%q,"name":"fixture","state":"started","region":"iad","config":{"env":{"CANARY":"must-not-return"}}}]`, user)
	}))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	tokens := map[string]string{"alice": mcpAccess(t, h, "alice"), "bob": mcpAccess(t, h, "bob")}
	init := mcpRPC(t, endpoint.URL, tokens["alice"], "initialize", map[string]any{
		"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "test", "version": "1"},
	})
	if init.Result.ServerInfo.Name != "Fly MCP" {
		t.Fatal("did not initialize the in-process server")
	}
	tools := mcpRPC(t, endpoint.URL, tokens["alice"], "tools/list", map[string]any{})
	var names []string
	for _, tool := range tools.Result.Tools {
		names = append(names, tool.Name)
		if tool.Annotations.ReadOnlyHint == tool.Annotations.DestructiveHint || tool.Annotations.ReadOnlyHint != tool.Annotations.IdempotentHint {
			t.Errorf("inconsistent annotations for %s", tool.Name)
		}
		if (tool.Name == "fly-machine-list" && !tool.Annotations.ReadOnlyHint) || (tool.Name == "fly-machine-exec" && tool.Annotations.ReadOnlyHint) {
			t.Errorf("incorrect effect classification for %s", tool.Name)
		}
	}
	slices.Sort(names)
	wantNames := strings.Fields(`fly-apps-create fly-apps-destroy fly-apps-list fly-apps-move fly-apps-releases fly-apps-restart
		fly-certs-add fly-certs-check fly-certs-list fly-certs-remove fly-certs-show
		fly-ips-allocate-v4 fly-ips-allocate-v6 fly-ips-list fly-ips-private fly-ips-release fly-logs
		fly-machine-clone fly-machine-cordon fly-machine-create fly-machine-destroy fly-machine-egress-ip-allocate
		fly-machine-egress-ip-list fly-machine-egress-ip-release fly-machine-exec fly-machine-kill fly-machine-leases-clear
		fly-machine-leases-view fly-machine-list fly-machine-restart fly-machine-run fly-machine-start fly-machine-status
		fly-machine-stop fly-machine-suspend fly-machine-upcordon fly-machine-update
		fly-orgs-create fly-orgs-delete fly-orgs-invite fly-orgs-list fly-orgs-remove fly-orgs-show
		fly-platform-regions fly-platform-status fly-platform-vm-sizes fly-secrets-deploy fly-secrets-list fly-secrets-set fly-secrets-unset fly-status
		fly-volumes-create fly-volumes-destroy fly-volumes-extend fly-volumes-fork fly-volumes-list fly-volumes-show
		fly-volumes-snapshots-create fly-volumes-snapshots-list fly-volumes-update`)
	if !slices.Equal(names, wantNames) {
		t.Fatalf("unexpected tool surface: %v", names)
	}
	for _, args := range []map[string]any{{}, {"app": "../other"}, {"app": "--help"}, {"app": 1}, {"app": "alice", "access-token": "other"}} {
		result := mcpRPC(t, endpoint.URL, tokens["alice"], "tools/call", map[string]any{"name": "fly-machine-list", "arguments": args})
		if result.Error == nil && !result.Result.IsError {
			t.Error("invalid arguments accepted")
		}
	}
	removed := mcpRPC(t, endpoint.URL, tokens["alice"], "tools/call", map[string]any{"name": "fly-unknown", "arguments": map[string]string{"name": "alice"}})
	if removed.Error == nil && !removed.Result.IsError {
		t.Fatal("unknown tool remained callable")
	}
	if calls.Load() != 0 {
		t.Fatal("discovery or invalid calls reached Fly")
	}
	var wg sync.WaitGroup
	for user, token := range tokens {
		wg.Go(func() {
			result := mcpRPC(t, endpoint.URL, token, "tools/call", map[string]any{"name": "fly-machine-list", "arguments": map[string]string{"app": user}})
			if result.Error != nil || result.Result.IsError || len(result.Result.Content) != 1 {
				t.Error("machine call failed")
				return
			}
			want := `[{"id":"` + user + `","name":"fixture","state":"started","region":"iad"}]`
			if result.Result.Content[0].Text != want {
				t.Error("wrong caller's data or leaked Machine configuration")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatal("tool calls performed additional API requests")
	}
}

func TestMCPGraphQLPaginationAndOrganizationFilter(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Query     string
			Variables map[string]any
		}
		if r.Method != "POST" || r.URL.Path != "/graphql" || json.NewDecoder(r.Body).Decode(&request) != nil || strings.Contains(request.Query, "mutation") {
			t.Error("unexpected GraphQL request")
			w.WriteHeader(400)
			return
		}
		isOrgs := strings.Contains(request.Query, "FlyMCPListOrganizations")
		wantAuth := "FlyV1 fm2_alice,fo1_alice"
		if isOrgs {
			wantAuth = "Bearer fo1_alice"
		}
		if r.Header.Get("Authorization") != wantAuth {
			t.Error("wrong GraphQL credential")
			w.WriteHeader(401)
			return
		}
		if strings.Contains(request.Query, "FlyMCPAppOrganization") {
			if request.Variables["slug"] != "second-org" {
				t.Error("lost organization filter")
			}
			_, _ = io.WriteString(w, `{"data":{"organization":{"id":"ORG-B"}}}`)
			return
		}
		field := "apps"
		if isOrgs {
			field = "organizations"
		} else if request.Variables["org"] != "ORG-B" {
			t.Error("app query lost resolved organization ID")
		}
		id, next := "first", true
		if request.Variables["after"] != nil {
			if request.Variables["after"] != "next-page" {
				t.Error("unexpected cursor")
			}
			id, next = "second", false
		}
		_, _ = fmt.Fprintf(w, `{"data":{%q:{"nodes":[{"id":%q,"name":%q,"slug":%q}],"pageInfo":{"hasNextPage":%t,"endCursor":"next-page"}}}}`, field, id, id, id, next)
	}))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	token := mcpAccess(t, h, "alice")
	for _, spec := range []struct {
		name string
		args map[string]string
	}{
		{"fly-orgs-list", map[string]string{}}, {"fly-apps-list", map[string]string{"org": "second-org"}},
	} {
		result := mcpRPC(t, endpoint.URL, token, "tools/call", map[string]any{"name": spec.name, "arguments": spec.args})
		if result.Error != nil || result.Result.IsError || len(result.Result.Content) != 1 {
			t.Fatal("listing failed")
		}
		var rows []struct{ ID string }
		if json.Unmarshal([]byte(result.Result.Content[0].Text), &rows) != nil || len(rows) != 2 || rows[0].ID != "first" || rows[1].ID != "second" {
			t.Fatal("listing omitted or duplicated a page")
		}
	}
	if calls.Load() != 5 {
		t.Fatal("unexpected discovery, minting or API calls")
	}
}

func TestMCPUpstreamFailuresAreSafe(t *testing.T) {
	const canary = "fo1_PRIVATE_UPSTREAM_CANARY"
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	var redirected atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
	defer other.Close()
	for _, code := range []int{401, 502, 302, 200} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", other.URL)
				w.WriteHeader(code)
				_, _ = io.WriteString(w, `{"errors":[{"message":"permission denied `+canary+`"}]}`)
			}))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			endpoint := httptest.NewServer(h)
			defer endpoint.Close()
			token := mcpAccess(t, h, "alice")
			for _, tool := range []string{"fly-machine-list", "fly-apps-list"} {
				args := map[string]string{}
				if tool == "fly-machine-list" {
					args["app"] = "fixture"
				}
				result := mcpRPC(t, endpoint.URL, token, "tools/call", map[string]any{"name": tool, "arguments": args})
				encoded, _ := json.Marshal(result)
				if !result.Result.IsError || strings.Contains(string(encoded), canary) || strings.Contains(logs.String(), canary) {
					t.Fatal("upstream error was accepted or leaked")
				}
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("upstream redirect received credentials")
	}
}

func TestMCPWritesStayBoundToCaller(t *testing.T) {
	t.Setenv("FLY_API_TOKEN", "ambient-must-not-be-used")
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/apps/"), "/secrets")
		var body struct{ Values map[string]string }
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || r.Header.Get("Authorization") != "FlyV1 fm2_"+user || body.Values["TOKEN"] != "private-"+user {
			t.Error("mutation used another caller's credential, argument or endpoint")
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, `{"version":4,"secrets":[{"name":"TOKEN","digest":"digest","value":"must-not-return"}]}`)
	}))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	tokens := map[string]string{"alice": mcpAccess(t, h, "alice"), "bob": mcpAccess(t, h, "bob")}
	invalid := mcpRPC(t, endpoint.URL, tokens["alice"], "tools/call", map[string]any{"name": "fly-secrets-set", "arguments": map[string]any{"app": "alice", "keyvalues": []any{"TOKEN=private-alice"}, "endpoint": api.URL}})
	if !invalid.Result.IsError || calls.Load() != 0 {
		t.Fatal("invalid write reached upstream")
	}
	var wg sync.WaitGroup
	for user, token := range tokens {
		wg.Go(func() {
			result := mcpRPC(t, endpoint.URL, token, "tools/call", map[string]any{"name": "fly-secrets-set", "arguments": map[string]any{"app": user, "keyvalues": []any{"TOKEN=private-" + user}}})
			encoded, _ := json.Marshal(result)
			if result.Error != nil || result.Result.IsError || strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "must-not-return") {
				t.Error("mutation failed or returned secret values")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("writes performed %d requests", calls.Load())
	}
}
