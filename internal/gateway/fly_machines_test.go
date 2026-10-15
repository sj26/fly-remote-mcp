package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const machineTestCredential = "FlyV1 fm2_test,fo1_test"

func TestMachineToolHandlersComplete(t *testing.T) {
	c := &flyClient{}
	if got := len(c.machineToolHandlers()); got != 20 {
		t.Fatalf("got %d machine handlers, want 20", got)
	}
}

func TestMachineCreateProtocol(t *testing.T) {
	var calls int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/apps/demo/machines" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "FlyV1 fm2_test" {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["skip_launch"] != true {
			t.Errorf("create must skip launch: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"abc","state":"created"}`))
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	_, err := c.machineToolHandlers()["fly-machine-create"](context.Background(), machineTestCredential, toolArguments{"app": "demo", "image": "registry/image:tag"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestMachineUpdatePreservesOmittedFieldsAndUsesLease(t *testing.T) {
	var step int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		w.Header().Set("Content-Type", "application/json")
		switch step {
		case 1:
			_, _ = w.Write([]byte(`{"id":"abc","state":"stopped","instance_id":"old-instance","config":{"image":"old","env":{"KEEP":"yes"},"schedule":"daily","init":{"cmd":["old"],"future":"preserve"},"dns":{"skip_registration":true,"future":7},"guest":{"cpus":2,"memory_mb":4096,"future":8},"services":[{"autostart":true,"autostop":"stop","future":9}],"standbys":["old"],"future":{"nested":"keep"}}}`))
		case 2:
			if r.Method != http.MethodPost || r.URL.Query().Get("ttl") != "270" {
				t.Errorf("bad lease acquisition")
			}
			_, _ = w.Write([]byte(`{"data":{"nonce":"lease-nonce"}}`))
		case 3:
			if r.Header.Get(leaseHeader) != "lease-nonce" || r.Header.Get("fly-machine-instance-id") != "" {
				t.Errorf("missing optimistic headers")
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			var want map[string]any
			_ = json.Unmarshal([]byte(`{"image":"new","env":{"KEEP":"yes"},"schedule":"daily","init":{"cmd":[],"future":"preserve"},"dns":{"skip_registration":false,"future":7},"guest":{"cpus":2,"memory_mb":1024,"future":8},"services":[{"autostart":false,"autostop":"off","future":9}],"standbys":[],"future":{"nested":"keep"}}`), &want)
			if body["current_version"] != "old-instance" || body["skip_launch"] != true || !reflect.DeepEqual(body["config"], want) {
				t.Errorf("update lost configuration or explicit false/empty: %#v", body)
			}
			_, _ = w.Write([]byte(`{"id":"abc"}`))
		case 4:
			if r.Method != http.MethodDelete || r.Header.Get(leaseHeader) != "lease-nonce" {
				t.Errorf("bad lease cleanup")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected extra request")
		}
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	_, err := c.machineUpdate(context.Background(), machineTestCredential, toolArguments{"app": "demo", "id": "abc", "image": "new", "command": "", "skip-dns-registration": false, "vm-memory": float64(1024), "autostart": false, "autostop": "off", "standby-for": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if step != 4 {
		t.Fatalf("steps = %d", step)
	}
}

func TestMachineExecUsesRemoteEndpoint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/demo/machines/abc/exec" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["cmd"] != "echo hello" {
			t.Errorf("body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"exit_code":7,"stdout":"hello\n"}`))
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	if result, err := c.machineExec(context.Background(), machineTestCredential, toolArguments{"app": "demo", "id": "abc", "command": "echo hello"}); err == nil || result == nil {
		t.Fatal("nonzero remote exit must preserve output and return an error")
	}
}

func TestMachineCloneVolumeAndPartialFailure(t *testing.T) {
	var step int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			_, _ = w.Write([]byte(`{"id":"source","region":"iad","config":{"image":"image","init":{"future":"keep"},"mounts":[{"volume":"vol_old","path":"/data"}],"auto_destroy":true,"future":"keep"}}`))
		case 2:
			if r.Method != "GET" || r.URL.Path != "/v1/apps/demo/volumes/vol_old" {
				t.Error("missing source volume lookup")
			}
			_, _ = w.Write([]byte(`{"id":"vol_old","name":"data","size_gb":3,"encrypted":true}`))
		case 3:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.Method != "POST" || r.URL.Path != "/v1/apps/demo/volumes" || body["size_gb"] != float64(3) || body["name"] != "data" || body["require_unique_zone"] != true {
				t.Errorf("bad clone volume: %#v", body)
			}
			_, _ = w.Write([]byte(`{"id":"vol_new"}`))
		case 4:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			cfg, _ := body["config"].(map[string]any)
			if body["skip_launch"] != false || cfg["future"] != "keep" || cfg["auto_destroy"] != false {
				t.Errorf("bad clone config: %#v", body)
			}
			w.WriteHeader(503)
		default:
			t.Error("failed write was retried or cleanup attempted")
		}
	}))
	defer s.Close()
	c := &flyClient{machinesURL: s.URL, httpClient: s.Client()}
	_, err := c.machineClone(context.Background(), machineTestCredential, toolArguments{"app": "demo", "id": "source", "clear-auto-destroy": true})
	if err == nil || !strings.Contains(err.Error(), "vol_new") || step != 4 {
		t.Fatalf("missing partial creation report: %v (%d calls)", err, step)
	}
}
