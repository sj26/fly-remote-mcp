package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"

	fly "github.com/superfly/fly-go"
)

const platformStatusEndpoint = "https://status.flyio.net/api/v2/status.json"

func resourcePath(app, resource string) string { return appAPIPath(app) + "/" + resource }
func itemPath(base, id string) string          { return base + "/" + url.PathEscape(id) }

// resourceToolHandlers contains the native implementations of the cert, IP,
// volume and platform commands. Every request goes through the deliberately
// retry-free transport in fly_native.go.
func (c *flyClient) resourceToolHandlers() map[string]nativeToolHandler {
	h := map[string]nativeToolHandler{}

	certBase := func(a toolArguments) string { return resourcePath(a.text("app"), "certificates") }
	h["fly-certs-add"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out fly.CertificateDetailResponse
		err := c.machinesRequest(ctx, credential, http.MethodPost, certBase(a)+"/acme", fly.CreateCertificateRequest{Hostname: a.text("hostname")}, &out)
		return out, err
	}
	h["fly-certs-check"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out fly.CertificateDetailResponse
		err := c.machinesRequest(ctx, credential, http.MethodPost, itemPath(certBase(a), a.text("hostname"))+"/check", nil, &out)
		return out, err
	}
	h["fly-certs-show"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out fly.CertificateDetailResponse
		err := c.machinesRequest(ctx, credential, http.MethodGet, itemPath(certBase(a), a.text("hostname")), nil, &out)
		return out, err
	}
	h["fly-certs-remove"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		err := c.machinesRequest(ctx, credential, http.MethodDelete, itemPath(certBase(a), a.text("hostname")), nil, nil)
		return map[string]any{"removed": err == nil, "hostname": a.text("hostname")}, err
	}
	h["fly-certs-list"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		all := make([]fly.CertificateSummary, 0)
		cursor := ""
		for page := 0; page < 100; page++ {
			q := url.Values{"limit": {"100"}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			var out fly.ListCertificatesResponse
			if err := c.machinesRequest(ctx, credential, http.MethodGet, certBase(a)+"?"+q.Encode(), nil, &out); err != nil {
				return nil, err
			}
			all = append(all, out.Certificates...)
			if out.NextCursor == "" {
				return all, nil
			}
			if out.NextCursor == cursor {
				return nil, errors.New("Fly returned invalid certificate pagination")
			}
			cursor = out.NextCursor
		}
		return nil, errors.New("Fly returned too many certificate pages")
	}

	ipBase := func(a toolArguments) string { return resourcePath(a.text("app"), "ip_assignments") }
	allocate := func(defaultKind string) nativeToolHandler {
		return func(ctx context.Context, credential string, a toolArguments) (any, error) {
			kind := defaultKind
			if kind == "v4" && a.flag("shared") {
				kind = "shared_v4"
			}
			if kind == "v6" && a.flag("private") {
				kind = "private_v6"
			}
			body := map[string]any{"type": kind, "region": "", "org_slug": "", "network": "", "service_name": ""}
			if (kind == "v4" || kind == "v6") && a.has("region") {
				body["region"] = a.text("region")
			}
			if kind == "private_v6" {
				body["org_slug"], body["network"] = a.text("org"), a.text("network")
			} else if a.has("org") || a.has("network") {
				return nil, errors.New("org and network require private IPv6 allocation")
			}
			var out map[string]any
			err := c.machinesRequest(ctx, credential, http.MethodPost, ipBase(a), body, &out)
			return out, err
		}
	}
	h["fly-ips-allocate-v4"] = allocate("v4")
	h["fly-ips-allocate-v6"] = allocate("v6")
	h["fly-ips-list"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out struct {
			IPs []map[string]any `json:"ips"`
		}
		err := c.machinesRequest(ctx, credential, http.MethodGet, ipBase(a), nil, &out)
		return out.IPs, err
	}
	h["fly-ips-release"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		addresses := a.list("addresses")
		if len(addresses) > 100 {
			return nil, errors.New("At most 100 IP addresses can be released at once")
		}
		for _, address := range addresses {
			if net.ParseIP(address) == nil {
				return nil, errors.New("Invalid IP address; no addresses released")
			}
		}
		released := make([]string, 0, len(addresses))
		for _, address := range addresses {
			if err := c.machinesRequest(ctx, credential, http.MethodDelete, itemPath(ipBase(a), address), nil, nil); err != nil {
				return map[string]any{"released": released, "failed": address}, err
			}
			released = append(released, address)
		}
		return map[string]any{"released": released}, nil
	}
	h["fly-ips-private"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var machines []struct {
			PrivateIP string `json:"private_ip"`
		}
		if err := c.machinesRequest(ctx, credential, http.MethodGet, resourcePath(a.text("app"), "machines"), nil, &machines); err != nil {
			return nil, err
		}
		ips := make([]string, 0, len(machines))
		for _, m := range machines {
			if m.PrivateIP != "" {
				ips = append(ips, m.PrivateIP)
			}
		}
		return ips, nil
	}

	volBase := func(a toolArguments) string { return resourcePath(a.text("app"), "volumes") }
	volume := func(method, suffix string, body func(toolArguments) any, out bool) nativeToolHandler {
		return func(ctx context.Context, credential string, a toolArguments) (any, error) {
			path := volBase(a)
			if a.text("id") != "" {
				path = itemPath(path, a.text("id"))
			}
			path += suffix
			var result any
			if out {
				result = &fly.Volume{}
			}
			var in any
			if body != nil {
				in = body(a)
			}
			err := c.machinesRequest(ctx, credential, method, path, in, result)
			if !out {
				return map[string]any{"ok": err == nil}, err
			}
			return result, err
		}
	}
	h["fly-volumes-create"] = volume(http.MethodPost, "", func(a toolArguments) any {
		size, encrypted := 1, true
		if a.has("size") {
			size = a.number("size")
		}
		if a.has("encrypt") {
			encrypted = a.flag("encrypt")
		}
		return fly.CreateVolumeRequest{Name: a.text("name"), Region: a.text("region"), SizeGb: &size, Encrypted: &encrypted}
	}, true)
	h["fly-volumes-destroy"] = volume(http.MethodDelete, "", nil, true)
	h["fly-volumes-extend"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out struct {
			Volume       *fly.Volume `json:"volume"`
			NeedsRestart bool        `json:"needs_restart"`
		}
		err := c.machinesRequest(ctx, credential, http.MethodPut, itemPath(volBase(a), a.text("id"))+"/extend", map[string]int{"size_gb": a.number("size")}, &out)
		if err == nil && out.Volume == nil {
			err = errors.New("Fly omitted the extended volume; inspect volume state before retrying")
		}
		return out, err
	}
	h["fly-volumes-fork"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		// Fork is a create with source_volume_id; an omitted region lets Machines
		// API preserve the source placement semantics.
		id := a.text("id")
		name := ""
		var source fly.Volume
		if err := c.machinesRequest(ctx, credential, http.MethodGet, itemPath(volBase(a), id), nil, &source); err != nil {
			return nil, err
		}
		name = source.Name
		body := fly.CreateVolumeRequest{Name: name, Region: a.text("region"), SourceVolumeID: &id}
		var out fly.Volume
		err := c.machinesRequest(ctx, credential, http.MethodPost, volBase(a), body, &out)
		return out, err
	}
	h["fly-volumes-list"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out []fly.Volume
		if err := c.machinesRequest(ctx, credential, http.MethodGet, volBase(a), nil, &out); err != nil {
			return nil, err
		}
		if !a.flag("all") {
			out = slices.DeleteFunc(out, func(v fly.Volume) bool {
				return slices.Contains([]string{"scheduling_destroy", "fork_cleanup", "waiting_for_detach", "pending_destroy", "destroying"}, v.State)
			})
		}
		return out, nil
	}
	h["fly-volumes-show"] = volume(http.MethodGet, "", nil, true)
	h["fly-volumes-snapshots-create"] = volume(http.MethodPost, "/snapshots", nil, false)
	h["fly-volumes-snapshots-list"] = func(ctx context.Context, credential string, a toolArguments) (any, error) {
		var out []fly.VolumeSnapshot
		err := c.machinesRequest(ctx, credential, http.MethodGet, itemPath(volBase(a), a.text("id"))+"/snapshots", nil, &out)
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
		return out, err
	}
	h["fly-volumes-update"] = volume(http.MethodPut, "", func(a toolArguments) any {
		body := fly.UpdateVolumeRequest{}
		if a.has("scheduled-snapshots") {
			v := a.flag("scheduled-snapshots")
			body.AutoBackupEnabled = &v
		}
		if a.has("snapshot-retention") {
			v := a.number("snapshot-retention")
			body.SnapshotRetention = &v
		}
		return body
	}, true)

	h["fly-platform-regions"] = func(ctx context.Context, credential string, _ toolArguments) (any, error) {
		var out struct {
			Regions []fly.Region `json:"Regions"`
			Nearest string       `json:"Nearest"`
		}
		if err := c.machinesRequest(ctx, credential, http.MethodGet, "/v1/platform/regions", nil, &out); err != nil {
			return nil, err
		}
		out.Regions = slices.DeleteFunc(out.Regions, func(r fly.Region) bool { return r.Deprecated })
		sort.Slice(out.Regions, func(i, j int) bool { return out.Regions[i].Name < out.Regions[j].Name })
		return out, nil
	}
	h["fly-platform-status"] = func(ctx context.Context, _ string, _ toolArguments) (any, error) {
		var out map[string]any
		err := c.nativeJSON(ctx, "", http.MethodGet, platformStatusEndpoint, nil, &out, nil)
		return out, err
	}
	h["fly-platform-vm-sizes"] = func(context.Context, string, toolArguments) (any, error) {
		out := make(map[string]fly.MachineGuest)
		for name, guest := range fly.MachinePresets {
			if guest.GPUKind == "" {
				out[name] = *guest
			}
		}
		return out, nil
	}
	return h
}
