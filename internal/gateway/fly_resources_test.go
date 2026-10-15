package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceToolHandlersSurface(t *testing.T) {
	c := &flyClient{}
	h := c.resourceToolHandlers()
	if len(h) != 22 {
		t.Fatalf("got %d resource handlers, want 22", len(h))
	}
	for _, name := range []string{"fly-certs-add", "fly-ips-private", "fly-volumes-update", "fly-platform-status"} {
		if h[name] == nil {
			t.Errorf("missing %s", name)
		}
	}
}

func TestVolumeCreateDefaultsAndExplicitFalse(t *testing.T) {
	var requests []map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/apps/my%20app/volumes" {
			t.Errorf("request = %s %s", r.Method, r.URL.EscapedPath())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"vol_1"}`))
	}))
	defer api.Close()
	c := &flyClient{machinesURL: api.URL, httpClient: api.Client()}
	h := c.resourceToolHandlers()["fly-volumes-create"]
	credential := "FlyV1 fm2_resources,fo1_resources"
	base := toolArguments{"app": "my app", "name": "data", "region": "ord"}
	if _, err := h(context.Background(), credential, base); err != nil {
		t.Fatal(err)
	}
	explicit := toolArguments{"app": "my app", "name": "data", "region": "ord", "encrypt": false, "size": float64(3)}
	if _, err := h(context.Background(), credential, explicit); err != nil {
		t.Fatal(err)
	}
	if requests[0]["encrypted"] != true || requests[0]["size_gb"] != float64(1) {
		t.Fatalf("default body = %#v", requests[0])
	}
	if requests[1]["encrypted"] != false || requests[1]["size_gb"] != float64(3) {
		t.Fatalf("explicit body = %#v", requests[1])
	}
}

func TestIPAllocationDoesNotRetainPreviousCallOptions(t *testing.T) {
	var kinds []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Type string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		kinds = append(kinds, body.Type)
		_, _ = w.Write([]byte(`{"address":"192.0.2.1"}`))
	}))
	defer api.Close()
	c := &flyClient{machinesURL: api.URL, httpClient: api.Client()}
	allocate := c.resourceToolHandlers()["fly-ips-allocate-v4"]
	for _, shared := range []bool{true, false} {
		if _, err := allocate(context.Background(), machineTestCredential, toolArguments{"app": "demo", "shared": shared}); err != nil {
			t.Fatal(err)
		}
	}
	if len(kinds) != 2 || kinds[0] != "shared_v4" || kinds[1] != "v4" {
		t.Fatalf("allocation kind leaked between calls: %v", kinds)
	}
}

func TestIPReleaseValidatesWholeBatchBeforeWriting(t *testing.T) {
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	defer api.Close()
	c := &flyClient{machinesURL: api.URL, httpClient: api.Client()}
	_, err := c.resourceToolHandlers()["fly-ips-release"](context.Background(), machineTestCredential, toolArguments{"app": "demo", "addresses": []any{"192.0.2.1", "invalid"}})
	if err == nil || calls != 0 {
		t.Fatal("invalid batch partially released addresses")
	}
}

func TestPlatformStatusUsesCanonicalPublicHostWithoutCredentials(t *testing.T) {
	var calls int
	c := &flyClient{httpClient: &http.Client{Transport: dischargeRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://status.flyio.net/api/v2/status.json" || r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Error("status used a redirecting host or sent credentials")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":{"indicator":"none","description":"All Systems Operational"}}`)), Header: make(http.Header)}, nil
	})}}
	result, err := c.resourceToolHandlers()["fly-platform-status"](context.Background(), machineTestCredential, toolArguments{})
	if err != nil || calls != 1 {
		t.Fatalf("status=%v, calls=%d", err, calls)
	}
	status := result.(map[string]any)["status"].(map[string]any)
	if status["indicator"] != "none" {
		t.Fatalf("wrong status result: %#v", result)
	}
}
