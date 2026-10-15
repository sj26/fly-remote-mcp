package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const accountTestCredential = "FlyV1 fm2_test,fo1_test"

func TestAccountCatalogHasExactlyEighteenHandlers(t *testing.T) {
	c := &flyClient{}
	if got := len(c.accountToolHandlers()); got != 18 {
		t.Fatalf("handler count = %d, want 18", got)
	}
}

func TestManagedAccountMachineFallsBackToLegacyProcessGroup(t *testing.T) {
	m := accountMachine{State: "started", Config: map[string]any{"metadata": map[string]any{
		"fly_platform_version": "v2", "process_group": "fly_app_console",
	}}}
	if managedAccountMachine(m) {
		t.Fatal("legacy console process group must be excluded")
	}
	m.Config["metadata"].(map[string]any)["process_group"] = "web"
	if !managedAccountMachine(m) {
		t.Fatal("ordinary legacy process group must be managed")
	}
}

func TestCreateAppUsesFlapsNameField(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["name"] != "demo" || body["app_name"] != nil || body["org_slug"] != "personal" {
			t.Fatalf("create body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"name":"demo"}`))
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	if _, err := c.createApp(context.Background(), accountTestCredential, toolArguments{"name": "demo", "org": "personal"}); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMachineForSecretsRejectsIncompletePreflightWithoutWrite(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	err := c.updateMachineForSecrets(context.Background(), accountTestCredential, "demo", accountMachine{ID: "m1", Config: map[string]any{}}, nil, false)
	if err == nil || requests != 0 {
		t.Fatalf("err = %v, requests = %d; want preflight failure without writes", err, requests)
	}
}

func TestSetSecretsStagesObjectWithoutReturningValues(t *testing.T) {
	var requests int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/apps/demo/secrets" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Values map[string]*string `json:"values"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Values["TOKEN"] == nil || *body.Values["TOKEN"] != "top-secret" {
			t.Fatalf("bad staged request: %#v (%v)", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":7,"secrets":[{"name":"TOKEN","digest":"sha256:x"}]}`))
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client(), now: time.Now}
	got, err := c.setSecrets(context.Background(), accountTestCredential, toolArguments{"app": "demo", "keyvalues": []any{"TOKEN=top-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "top-secret") {
		t.Fatalf("secret leaked in result: %s", b)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one (writes must not retry)", requests)
	}
}

func TestAppReleasesUsesAuthoritativeUnprocessedShape(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"releasesUnprocessed", "reason", "imageRef", "stable", "createdAt"} {
			if !strings.Contains(request.Query, required) {
				t.Errorf("query missing %q: %s", required, request.Query)
			}
		}
		for _, invalid := range []string{"updatedAt", " type "} {
			if strings.Contains(request.Query, invalid) {
				t.Errorf("query contains unsupported %q", invalid)
			}
		}
		if request.Variables["limit"] != float64(25) {
			t.Errorf("limit = %#v", request.Variables["limit"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"app":{"releases":{"nodes":[{"id":"r1","version":9,"reason":"deploy"}]}}}}`))
	}))
	defer s.Close()
	c := &flyClient{graphqlURL: s.URL, httpClient: s.Client()}
	result, err := c.appReleases(context.Background(), accountTestCredential, toolArguments{"name": "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["limit"] != 25 {
		t.Fatalf("result = %#v", result)
	}
}

func TestLogsHandlesNullAttributesAndPaginatesBoundedly(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"data":[{"id":"one","attributes":null}],"meta":{"next_token":"next"}}`))
			return
		}
		if r.URL.Query().Get("next_token") != "next" {
			t.Errorf("token = %q", r.URL.Query().Get("next_token"))
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"two","attributes":{"message":"ok"}}],"meta":{}}`))
	}))
	defer s.Close()
	c := &flyClient{graphqlURL: s.URL + "/graphql", httpClient: s.Client()}
	result, err := c.logs(context.Background(), accountTestCredential, toolArguments{"app": "demo"})
	if err != nil {
		t.Fatal(err)
	}
	entries := result.(map[string]any)["entries"].([]map[string]any)
	if len(entries) != 2 || entries[0]["id"] != "one" {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestUnsetSecretsUsesNullAndDoesNotRetry(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if value, exists := body["values"]["OLD"]; !exists || value != nil {
			t.Fatalf("unset value = %#v", body)
		}
		http.Error(w, "sensitive upstream body", http.StatusServiceUnavailable)
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	_, err := c.unsetSecrets(context.Background(), accountTestCredential, toolArguments{"app": "demo", "names": []any{"OLD"}})
	if err == nil || strings.Contains(err.Error(), "sensitive upstream body") {
		t.Fatalf("unsafe error: %v", err)
	}
	if requests != 1 {
		t.Fatalf("write retried %d times", requests)
	}
}

func TestDeploySecretsPreservesStoppedConfiguration(t *testing.T) {
	var step int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			if r.Method != "GET" || r.URL.Path != "/v1/apps/demo/machines" {
				t.Error("unexpected discovery")
			}
			_, _ = w.Write([]byte(`[{"id":"m1","instance_id":"version1","state":"stopped","config":{"image":"image","future":"keep","metadata":{"fly_platform_version":"v2"}}}]`))
		case 2:
			if r.Method != "POST" || r.URL.Path != "/v1/apps/demo/machines/m1/lease" {
				t.Error("expected lease, not a secrets-version lookup")
			}
			_, _ = w.Write([]byte(`{"data":{"nonce":"nonce"}}`))
		case 3:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			cfg, _ := body["config"].(map[string]any)
			if r.Method != "POST" || r.Header.Get(leaseHeader) != "nonce" || body["skip_launch"] != true || body["current_version"] != "version1" || cfg["future"] != "keep" {
				t.Errorf("bad secrets deployment: %#v", body)
			}
			_, _ = w.Write([]byte(`{"id":"m1","state":"stopped"}`))
		case 4:
			_, _ = w.Write([]byte(`{"id":"m1","state":"stopped"}`))
		case 5:
			if r.Method != "DELETE" || r.Header.Get(leaseHeader) != "nonce" {
				t.Error("missing lease cleanup")
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected request")
		}
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	result, err := c.deploySecrets(context.Background(), accountTestCredential, toolArguments{"app": "demo"})
	if err != nil || step != 5 {
		t.Fatalf("deployment = %#v, %v; requests=%d", result, err, step)
	}
}

func TestMoveAppLeasesUnmanagedMachinesBeforeMoving(t *testing.T) {
	var step int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			_, _ = w.Write([]byte(`{"data":{"organization":{"id":"org-target"}}}`))
		case 2:
			_, _ = w.Write([]byte(`[{"id":"m1","instance_id":"v1","state":"started","config":{"image":"image"}},{"id":"m2","instance_id":"v2","state":"stopped","config":{"image":"other"}}]`))
		case 3:
			if r.URL.Path != "/v1/apps/demo/machines/m1/lease" {
				t.Error("app moved before acquiring standalone Machine leases")
			}
			_, _ = w.Write([]byte(`{"data":{"nonce":"first-nonce"}}`))
		case 4:
			if r.URL.Path != "/v1/apps/demo/machines/m2/lease" {
				t.Error("did not acquire all leases")
			}
			w.WriteHeader(409)
		case 5:
			if r.Method != "DELETE" || r.URL.Path != "/v1/apps/demo/machines/m1/lease" || r.Header.Get(leaseHeader) != "first-nonce" {
				t.Error("failed preflight did not release its earlier lease")
			}
			w.WriteHeader(204)
		default:
			t.Error("mutation attempted after a lease conflict")
		}
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, graphqlURL: s.URL + "/graphql", httpClient: s.Client()}
	_, err := c.moveApp(context.Background(), accountTestCredential, toolArguments{"name": "demo", "org": "target"})
	if err == nil || step != 5 {
		t.Fatalf("move err=%v, requests=%d", err, step)
	}
}

func TestOrganizationDetailsUsesMemberEdgesAndPaginates(t *testing.T) {
	var calls int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var q struct {
			Query     string
			Variables map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if r.Header.Get("Authorization") != "Bearer fo1_test" || q.Variables["slug"] != "personal" {
			t.Error("wrong organization identity")
		}
		switch {
		case strings.Contains(q.Query, "FlyMCPOrganization"):
			_, _ = w.Write([]byte(`{"data":{"organization":{"id":"org1","slug":"personal"}}}`))
		case strings.Contains(q.Query, "memberships:members(") && strings.Contains(q.Query, "nodes:edges{role user:node{"):
			if q.Variables["after"] == nil {
				_, _ = w.Write([]byte(`{"data":{"organization":{"memberships":{"nodes":[{"role":"ADMIN","user":{"id":"u1","email":"one@example.test"}}],"pageInfo":{"hasNextPage":true,"endCursor":"page2"}}}}}`))
			} else {
				if q.Variables["after"] != "page2" {
					t.Error("member cursor lost")
				}
				_, _ = w.Write([]byte(`{"data":{"organization":{"memberships":{"nodes":[{"role":"MEMBER","user":{"id":"u2","email":"two@example.test"}}],"pageInfo":{"hasNextPage":false}}}}}`))
			}
		case strings.Contains(q.Query, "invitations(first:"):
			_, _ = w.Write([]byte(`{"data":{"organization":{"invitations":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}`))
		default:
			t.Error("query does not match Fly Organization.members edge schema")
			_, _ = w.Write([]byte(`{"errors":[{"message":"invalid field"}]}`))
		}
	}))
	defer s.Close()
	c := &flyClient{graphqlURL: s.URL + "/graphql", httpClient: s.Client()}
	result, err := c.showOrg(context.Background(), accountTestCredential, toolArguments{"slug": "personal"})
	if err != nil || calls != 4 {
		t.Fatalf("org=%v, err=%v, calls=%d", result, err, calls)
	}
	org := result.(map[string]any)
	nodes := org["memberships"].(map[string]any)["nodes"].([]map[string]any)
	if len(nodes) != 2 || nodes[0]["role"] != "ADMIN" || nodes[1]["user"].(map[string]any)["id"] != "u2" {
		t.Fatalf("lost role/user/page: %#v", nodes)
	}
}
