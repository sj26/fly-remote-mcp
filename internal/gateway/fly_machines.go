package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/shlex"
	fly "github.com/superfly/fly-go"
)

const leaseHeader = "fly-machine-lease-nonce"

func machinePath(app, id string) string {
	p := appAPIPath(app) + "/machines"
	if id != "" {
		p += "/" + url.PathEscape(id)
	}
	return p
}

func (c *flyClient) machineToolHandlers() map[string]nativeToolHandler {
	h := map[string]nativeToolHandler{}
	h["fly-machine-list"] = func(ctx context.Context, cred string, a toolArguments) (any, error) {
		return c.listMachines(ctx, cred, a.text("app"))
	}
	h["fly-machine-status"] = c.machineStatus
	h["fly-machine-create"] = c.machineCreate(false)
	h["fly-machine-run"] = c.machineCreate(true)
	h["fly-machine-update"] = c.machineUpdate
	h["fly-machine-clone"] = c.machineClone
	h["fly-machine-exec"] = c.machineExec
	h["fly-machine-start"] = c.machineAction("start", "started")
	h["fly-machine-kill"] = c.machineSignal
	h["fly-machine-cordon"] = c.machineAction("cordon", "cordoned")
	h["fly-machine-upcordon"] = c.machineAction("uncordon", "uncordoned")
	h["fly-machine-suspend"] = c.machineActionWait("suspend", "suspended")
	h["fly-machine-stop"] = c.machineStop
	h["fly-machine-restart"] = c.machineRestart
	h["fly-machine-destroy"] = c.machineDestroy
	h["fly-machine-leases-view"] = c.machineLeaseView
	h["fly-machine-leases-clear"] = c.machineLeaseClear
	h["fly-machine-egress-ip-allocate"] = c.machineEgress("allocate")
	h["fly-machine-egress-ip-list"] = c.machineEgress("list")
	h["fly-machine-egress-ip-release"] = c.machineEgress("release")
	return h
}

func (c *flyClient) machineStatus(ctx context.Context, cred string, a toolArguments) (any, error) {
	var m fly.Machine
	if err := c.machinesRequest(ctx, cred, http.MethodGet, machinePath(a.text("app"), a.text("id")), nil, &m); err != nil {
		return nil, err
	}
	if !a.flag("display-config") {
		m.Config = nil
		m.IncompleteConfig = nil
	}
	return &m, nil
}

func pairs(items []string) (map[string]string, error) {
	m := map[string]string{}
	for _, s := range items {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, errors.New("values must use NAME=VALUE format")
		}
		m[k] = v
	}
	return m, nil
}
func words(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	v, e := shlex.Split(s)
	if e != nil {
		return nil, errors.New("command contains invalid shell quoting")
	}
	return v, nil
}

func parsePorts(values []string, creation bool, a toolArguments) ([]fly.MachineService, error) {
	services := map[string]*fly.MachineService{}
	for _, value := range values {
		left, right, _ := strings.Cut(value, "/")
		parts := strings.Split(left, ":")
		external, err := strconv.Atoi(parts[0])
		if err != nil || external < 1 || external > 65535 || len(parts) > 2 {
			return nil, fmt.Errorf("invalid port %q", value)
		}
		internal := external
		if len(parts) == 2 {
			internal, err = strconv.Atoi(parts[1])
			if err != nil || internal < 1 || internal > 65535 {
				return nil, fmt.Errorf("invalid machine port %q", value)
			}
		}
		protocol, handlers := "tcp", []string(nil)
		if right != "" {
			r := strings.Split(right, ":")
			protocol = r[0]
			if protocol != "tcp" && protocol != "udp" {
				return nil, fmt.Errorf("invalid port protocol %q", protocol)
			}
			handlers = r[1:]
			for _, h := range handlers {
				if h != "http" && h != "tls" && h != "proxy_proto" {
					return nil, fmt.Errorf("invalid port handler %q", h)
				}
			}
		}
		key := fmt.Sprintf("%s:%d", protocol, internal)
		s := services[key]
		if s == nil {
			s = &fly.MachineService{Protocol: protocol, InternalPort: internal}
			if creation {
				on := true
				off := fly.MachineAutostopOff
				s.Autostart, s.Autostop = &on, &off
			}
			if a.has("autostart") {
				v := a.flag("autostart")
				s.Autostart = &v
			}
			if a.has("autostop") {
				v := fly.MachineAutostopOff
				if a.text("autostop") == "stop" {
					v = fly.MachineAutostopStop
				} else if a.text("autostop") == "suspend" {
					v = fly.MachineAutostopSuspend
				}
				s.Autostop = &v
			}
			services[key] = s
		}
		p := external
		s.Ports = append(s.Ports, fly.MachinePort{Port: &p, Handlers: handlers})
	}
	out := make([]fly.MachineService, 0, len(services))
	for _, s := range services {
		out = append(out, *s)
	}
	return out, nil
}

func configFromArgs(a toolArguments, base *fly.MachineConfig, creation bool) (*fly.MachineConfig, error) {
	var cfg fly.MachineConfig
	if base != nil {
		cfg = *base
	}
	if a.has("image") {
		cfg.Image = a.text("image")
	}
	if creation && cfg.Image == "" {
		return nil, errors.New("image is required")
	}
	if a.has("env") {
		v, e := pairs(a.list("env"))
		if e != nil {
			return nil, e
		}
		if cfg.Env == nil {
			cfg.Env = map[string]string{}
		}
		for k, x := range v {
			cfg.Env[k] = x
		}
	}
	if a.has("metadata") {
		v, e := pairs(a.list("metadata"))
		if e != nil {
			return nil, e
		}
		if cfg.Metadata == nil {
			cfg.Metadata = map[string]string{}
		}
		for k, x := range v {
			cfg.Metadata[k] = x
		}
	}
	if a.has("command") {
		v, e := words(a.text("command"))
		if e != nil {
			return nil, e
		}
		cfg.Init.Cmd = v
	}
	if a.has("entrypoint") {
		v, e := words(a.text("entrypoint"))
		if e != nil {
			return nil, e
		}
		cfg.Init.Entrypoint = v
	}
	if a.has("schedule") {
		cfg.Schedule = a.text("schedule")
	}
	if a.has("rm") {
		cfg.AutoDestroy = a.flag("rm")
	}
	if a.has("standby-for") {
		cfg.Standbys = a.list("standby-for")
	}
	if a.has("skip-dns-registration") {
		if cfg.DNS == nil {
			cfg.DNS = &fly.DNSConfig{}
		}
		cfg.DNS.SkipRegistration = a.flag("skip-dns-registration")
	}
	if a.has("restart") {
		cfg.Restart = &fly.MachineRestart{Policy: fly.MachineRestartPolicy(a.text("restart"))}
	}
	if a.has("vm-size") {
		g, ok := fly.MachinePresets[a.text("vm-size")]
		if !ok {
			return nil, errors.New("unknown VM size")
		}
		x := *g
		cfg.Guest = &x
	}
	if a.has("vm-cpus") || a.has("vm-memory") || a.has("vm-cpu-kind") {
		if cfg.Guest == nil {
			cfg.Guest = &fly.MachineGuest{}
		}
		if a.has("vm-cpus") {
			cfg.Guest.CPUs = a.number("vm-cpus")
		}
		if a.has("vm-memory") {
			cfg.Guest.MemoryMB = a.number("vm-memory")
		}
		if a.has("vm-cpu-kind") {
			cfg.Guest.CPUKind = a.text("vm-cpu-kind")
		}
	}
	if a.has("host-dedication-id") {
		if cfg.Guest == nil {
			cfg.Guest = &fly.MachineGuest{}
		}
		cfg.Guest.HostDedicationID = a.text("host-dedication-id")
	}
	if a.has("port") {
		var e error
		cfg.Services, e = parsePorts(a.list("port"), creation, a)
		if e != nil {
			return nil, e
		}
	}
	if !a.has("port") && (a.has("autostart") || a.has("autostop")) {
		for i := range cfg.Services {
			if a.has("autostart") {
				v := a.flag("autostart")
				cfg.Services[i].Autostart = &v
			}
			if a.has("autostop") {
				v := fly.MachineAutostopOff
				if a.text("autostop") == "stop" {
					v = fly.MachineAutostopStop
				} else if a.text("autostop") == "suspend" {
					v = fly.MachineAutostopSuspend
				}
				cfg.Services[i].Autostop = &v
			}
		}
	}
	if a.has("volume") {
		for _, v := range a.list("volume") {
			p := strings.Split(v, ":")
			if len(p) < 2 || p[0] == "" || p[1] == "" {
				return nil, fmt.Errorf("invalid volume attachment %q", v)
			}
			m := fly.MachineMount{Volume: p[0], Path: p[1]}
			for _, option := range p[2:] {
				k, value, ok := strings.Cut(option, "=")
				n, err := strconv.Atoi(value)
				if !ok || err != nil {
					return nil, fmt.Errorf("invalid volume option %q", option)
				}
				switch k {
				case "extend_threshold_percent":
					m.ExtendThresholdPercent = n
				case "add_size_gb":
					m.AddSizeGb = n
				case "size_gb_limit":
					m.SizeGbLimit = n
				case "add_size_percent":
					m.AddSizePercent = n
				case "min_add_size_gb":
					m.MinAddSizeGb = n
				default:
					return nil, fmt.Errorf("unknown volume option %q", k)
				}
			}
			cfg.Mounts = append(cfg.Mounts, m)
		}
	}
	if a.has("user") {
		if len(cfg.Processes) == 0 {
			cfg.Processes = []fly.MachineProcess{{}}
		}
		cfg.Processes[0].UserOverride = a.text("user")
	}
	return &cfg, nil
}

func (c *flyClient) machineCreate(run bool) nativeToolHandler {
	return func(ctx context.Context, cred string, a toolArguments) (any, error) {
		if a.flag("use-zstd") {
			return nil, errors.New("use-zstd image compression is not supported by the Machines API")
		}
		if a.has("id") {
			return nil, errors.New("a Machine ID cannot be selected when creating through the Machines API")
		}
		cfg, e := configFromArgs(a, nil, true)
		if e != nil {
			return nil, e
		}
		for i := range cfg.Mounts {
			mount := &cfg.Mounts[i]
			if strings.HasPrefix(mount.Volume, "vol_") {
				continue
			}
			var volumes []fly.Volume
			if e = c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app"))+"/volumes", nil, &volumes); e != nil {
				return nil, e
			}
			id := ""
			for _, v := range volumes {
				if v.Name == mount.Volume && !v.IsAttached() && v.State == "created" && (a.text("region") == "" || v.Region == a.text("region")) {
					if id != "" {
						return nil, errors.New("Volume name is ambiguous; supply a volume ID")
					}
					id = v.ID
				}
			}
			if id == "" {
				return nil, errors.New("No available volume matches the requested name and region")
			}
			mount.Volume = id
		}
		in := map[string]any{"config": cfg, "region": a.text("region"), "name": a.text("name"), "skip_launch": !run}
		var out fly.Machine
		if e = c.machinesRequest(ctx, cred, http.MethodPost, machinePath(a.text("app"), ""), in, &out); e != nil {
			return nil, e
		}
		return &out, nil
	}
}

func (c *flyClient) getMachine(ctx context.Context, cred, app, id string) (*fly.Machine, error) {
	var m fly.Machine
	e := c.machinesRequest(ctx, cred, http.MethodGet, machinePath(app, id), nil, &m)
	return &m, e
}
func (c *flyClient) machineUpdate(ctx context.Context, cred string, a toolArguments) (any, error) {
	app, id := a.text("app"), a.text("id")
	if a.flag("use-zstd") {
		return nil, errors.New("use-zstd requires an image build; supply an existing image instead")
	}
	var raw map[string]json.RawMessage
	e := c.machinesRequest(ctx, cred, http.MethodGet, machinePath(app, id), nil, &raw)
	if e != nil {
		return nil, e
	}
	var instance string
	_ = json.Unmarshal(raw["instance_id"], &instance)
	var cfgMap map[string]any
	if instance == "" || json.Unmarshal(raw["config"], &cfgMap) != nil || cfgMap == nil {
		return nil, errors.New("machine configuration is unavailable and cannot be updated safely")
	}
	if e = patchMachineConfig(cfgMap, a); e != nil {
		return nil, e
	}
	var state string
	_ = json.Unmarshal(raw["state"], &state)
	in := map[string]any{"config": cfgMap, "current_version": instance, "skip_launch": state != "started"}
	var out fly.Machine
	e = c.withMachineLease(ctx, cred, app, id, func(x context.Context, nonce string) error {
		h := http.Header{}
		h.Set(leaseHeader, nonce)
		if err := c.machinesRequestHeaders(x, cred, http.MethodPost, machinePath(app, id), in, &out, h); err != nil {
			return err
		}
		if a.has("wait-timeout") {
			target := "stopped"
			if state == "started" {
				target = "started"
			}
			return c.waitMachineState(x, cred, app, id, target, time.Duration(a.number("wait-timeout"))*time.Second)
		}
		return nil
	})
	return &out, e
}

// Patch only requested leaves. Re-encoding SDK structs would discard future
// fields and omit explicit false/empty values, potentially changing the workload.
func patchMachineConfig(cfg map[string]any, a toolArguments) error {
	object := func(key string) map[string]any {
		m, _ := cfg[key].(map[string]any)
		if m == nil {
			m = map[string]any{}
			cfg[key] = m
		}
		return m
	}
	for _, key := range []string{"image", "schedule"} {
		if a.has(key) {
			cfg[key] = a.text(key)
		}
	}
	for _, key := range []string{"env", "metadata"} {
		if a.has(key) {
			values, err := pairs(a.list(key))
			if err != nil {
				return err
			}
			for k, v := range values {
				object(key)[k] = v
			}
		}
	}
	for arg, key := range map[string]string{"command": "cmd", "entrypoint": "entrypoint"} {
		if a.has(arg) {
			v, err := words(a.text(arg))
			if err != nil {
				return err
			}
			if v == nil {
				v = []string{}
			}
			object("init")[key] = v
		}
	}
	if a.has("standby-for") {
		cfg["standbys"] = a.list("standby-for")
	}
	if a.has("skip-dns-registration") {
		object("dns")["skip_registration"] = a.flag("skip-dns-registration")
	}
	if a.has("restart") {
		object("restart")["policy"] = a.text("restart")
	}
	if a.has("vm-size") {
		g, ok := fly.MachinePresets[a.text("vm-size")]
		if !ok {
			return errors.New("unknown VM size")
		}
		guest := object("guest")
		guest["cpu_kind"], guest["cpus"], guest["memory_mb"] = g.CPUKind, g.CPUs, g.MemoryMB
	}
	for arg, key := range map[string]string{"vm-cpus": "cpus", "vm-memory": "memory_mb", "vm-cpu-kind": "cpu_kind", "host-dedication-id": "host_dedication_id"} {
		if a.has(arg) {
			object("guest")[key] = a[arg]
		}
	}
	if a.has("port") {
		services, err := parsePorts(a.list("port"), false, a)
		if err != nil {
			return err
		}
		cfg["services"] = services
	} else if a.has("autostart") || a.has("autostop") {
		services, _ := cfg["services"].([]any)
		for _, value := range services {
			s, ok := value.(map[string]any)
			if !ok {
				return errors.New("invalid Machine service configuration")
			}
			if a.has("autostart") {
				s["autostart"] = a.flag("autostart")
			}
			if a.has("autostop") {
				s["autostop"] = a.text("autostop")
			}
		}
	}
	return nil
}

func (c *flyClient) machineClone(ctx context.Context, cred string, a toolArguments) (any, error) {
	var sourceRaw map[string]json.RawMessage
	e := c.machinesRequest(ctx, cred, http.MethodGet, machinePath(a.text("app"), a.text("id")), nil, &sourceRaw)
	if e != nil {
		return nil, e
	}
	var old fly.Machine
	if json.Unmarshal(machineJSON(sourceRaw), &old) != nil {
		return nil, errors.New("source machine response is invalid")
	}
	if old.Config == nil {
		return nil, errors.New("source machine configuration is unavailable")
	}
	cfg := *old.Config
	if updated, e2 := configFromArgs(a, &cfg, false); e2 != nil {
		return nil, e2
	} else {
		cfg = *updated
	}
	if a.flag("clear-auto-destroy") {
		cfg.AutoDestroy = false
	}
	if a.has("standby-for") {
		standbys := a.list("standby-for")
		for i := range standbys {
			if standbys[i] == "source" {
				standbys[i] = old.ID
			}
		}
		cfg.Standbys = standbys
		if cfg.Env == nil {
			cfg.Env = map[string]string{}
		}
		cfg.Env["FLY_STANDBY_FOR"] = strings.Join(standbys, ",")
	}
	if a.flag("clear-cmd") {
		cfg.Init.Cmd = []string{}
	}
	if a.has("override-cmd") {
		cfg.Init.Cmd, e = words(a.text("override-cmd"))
		if e != nil {
			return nil, e
		}
	}
	in := fly.LaunchMachineInput{Config: &cfg, Region: a.text("region"), Name: a.text("name"), SkipLaunch: len(cfg.Standbys) > 0}
	if in.Region == "" {
		in.Region = old.Region
	}
	created := []string{}
	if attach := a.text("attach-volume"); attach != "" {
		p := strings.SplitN(attach, ":", 2)
		var attached fly.Volume
		if e = c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app"))+"/volumes/"+url.PathEscape(p[0]), nil, &attached); e != nil {
			return nil, fmt.Errorf("could not get existing volume: %w", e)
		}
		if attached.IsAttached() {
			return nil, fmt.Errorf("volume %s is already attached to a machine", attached.ID)
		}
		if a.text("region") != "" && attached.Region != in.Region {
			return nil, fmt.Errorf("specified region %s but volume is in region %s", in.Region, attached.Region)
		}
		if a.text("region") == "" {
			in.Region = attached.Region
		}
		if len(cfg.Mounts) > 1 {
			return nil, errors.New("attach-volume cannot be used with more than one source volume")
		}
		path := ""
		if len(p) == 2 {
			path = p[1]
		} else if len(cfg.Mounts) == 1 {
			path = cfg.Mounts[0].Path
		}
		if path == "" {
			return nil, errors.New("attach-volume requires a mount path")
		}
		cfg.Mounts = []fly.MachineMount{{Volume: p[0], Path: path}}
	} else if len(cfg.Mounts) > 0 {
		mounts := append([]fly.MachineMount(nil), cfg.Mounts...)
		cfg.Mounts = nil
		for _, m := range mounts {
			var sourceVolume fly.Volume
			if e = c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app"))+"/volumes/"+url.PathEscape(m.Volume), nil, &sourceVolume); e != nil {
				return nil, fmt.Errorf("created volumes %v; source volume lookup failed: %w", created, e)
			}
			if sourceVolume.ID == "" || sourceVolume.Name == "" || sourceVolume.SizeGb <= 0 {
				return nil, fmt.Errorf("created volumes %v; source volume metadata is incomplete", created)
			}
			snapshot := a.text("from-snapshot")
			if snapshot == "last" {
				var ss []fly.VolumeSnapshot
				if e = c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app"))+"/volumes/"+url.PathEscape(m.Volume)+"/snapshots", nil, &ss); e != nil {
					return nil, fmt.Errorf("created volumes %v; snapshot lookup failed: %w", created, e)
				}
				snapshot = ""
				var latest time.Time
				for _, s := range ss {
					if s.CreatedAt.After(latest) {
						latest = s.CreatedAt
						snapshot = s.ID
					}
				}
				if snapshot == "" {
					return nil, fmt.Errorf("created volumes %v; no snapshot available", created)
				}
			}
			requireUnique := true
			if a.has("volume-requires-unique-zone") {
				requireUnique = a.flag("volume-requires-unique-zone")
			}
			body := map[string]any{"name": sourceVolume.Name, "region": in.Region, "size_gb": sourceVolume.SizeGb, "encrypted": sourceVolume.Encrypted, "require_unique_zone": requireUnique, "compute": cfg.Guest, "compute_image": cfg.Image}
			if snapshot != "" {
				body["snapshot_id"] = snapshot
			}
			var vol fly.Volume
			if e = c.machinesRequest(ctx, cred, http.MethodPost, appAPIPath(a.text("app"))+"/volumes", body, &vol); e != nil {
				return nil, fmt.Errorf("created volumes %v; volume creation failed: %w", created, e)
			}
			created = append(created, vol.ID)
			m.Volume = vol.ID
			cfg.Mounts = append(cfg.Mounts, m)
		}
	}
	var out fly.Machine
	var rawConfig map[string]any
	_ = json.Unmarshal(sourceRaw["config"], &rawConfig)
	if e = patchMachineConfig(rawConfig, a); e != nil {
		return nil, e
	}
	if len(old.Config.Mounts) > 0 || a.has("attach-volume") {
		rawConfig["mounts"] = cfg.Mounts
	}
	if a.has("standby-for") {
		rawConfig["standbys"], rawConfig["env"] = cfg.Standbys, cfg.Env
	}
	if a.has("override-cmd") {
		init, _ := rawConfig["init"].(map[string]any)
		if init == nil {
			init = map[string]any{}
			rawConfig["init"] = init
		}
		init["cmd"] = cfg.Init.Cmd
	}
	if a.flag("clear-auto-destroy") {
		rawConfig["auto_destroy"] = false
	}
	if a.flag("clear-cmd") {
		init, _ := rawConfig["init"].(map[string]any)
		if init == nil {
			init = map[string]any{}
		}
		init["cmd"] = []string{}
		rawConfig["init"] = init
	}
	request := map[string]any{"config": rawConfig, "region": in.Region, "name": in.Name, "skip_launch": in.SkipLaunch}
	e = c.machinesRequest(ctx, cred, http.MethodPost, machinePath(a.text("app"), ""), request, &out)
	if e != nil && len(created) > 0 {
		return &out, fmt.Errorf("created volumes %v; machine creation failed: %w", created, e)
	}
	return &out, e
}

func machineJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func (c *flyClient) machineExec(ctx context.Context, cred string, a toolArguments) (any, error) {
	var out fly.MachineExecResponse
	in := fly.MachineExecRequest{Cmd: a.text("command")}
	if in.Cmd == "" {
		return nil, errors.New("command is required")
	}
	e := c.machinesRequest(ctx, cred, http.MethodPost, machinePath(a.text("app"), a.text("id"))+"/exec", in, &out)
	if e == nil && out.ExitCode != 0 {
		e = fmt.Errorf("remote command exited with status %d", out.ExitCode)
	}
	return &out, e
}
func (c *flyClient) machineAction(action, msg string) nativeToolHandler {
	return func(ctx context.Context, cred string, a toolArguments) (any, error) {
		e := c.withMachineLease(ctx, cred, a.text("app"), a.text("id"), func(x context.Context, n string) error {
			h := http.Header{}
			h.Set(leaseHeader, n)
			return c.machinesRequestHeaders(x, cred, http.MethodPost, machinePath(a.text("app"), a.text("id"))+"/"+action, nil, nil, h)
		})
		if e != nil {
			return nil, e
		}
		return map[string]string{"status": msg}, e
	}
}
func (c *flyClient) machineActionWait(action, state string) nativeToolHandler {
	return func(ctx context.Context, cred string, a toolArguments) (any, error) {
		v := map[string]string{"status": state}
		e := c.withMachineLease(ctx, cred, a.text("app"), a.text("id"), func(x context.Context, n string) error {
			h := http.Header{}
			h.Set(leaseHeader, n)
			if err := c.machinesRequestHeaders(x, cred, http.MethodPost, machinePath(a.text("app"), a.text("id"))+"/"+action, nil, nil, h); err != nil {
				return err
			}
			t := time.Duration(a.number("wait-timeout")) * time.Second
			if t == 0 {
				t = 5 * time.Minute
			}
			return c.waitMachineState(x, cred, a.text("app"), a.text("id"), state, t)
		})
		if e != nil {
			return nil, e
		}
		return v, e
	}
}
func (c *flyClient) machineSignal(ctx context.Context, cred string, a toolArguments) (any, error) {
	e := c.machinesRequest(ctx, cred, http.MethodPost, machinePath(a.text("app"), a.text("id"))+"/signal", map[string]int{"signal": 9}, nil)
	if e != nil {
		return nil, e
	}
	return map[string]string{"status": "kill signal sent"}, nil
}
func (c *flyClient) machineStop(ctx context.Context, cred string, a toolArguments) (any, error) {
	body := map[string]any{"signal": a.text("signal")}
	if body["signal"] == "" {
		body["signal"] = "SIGTERM"
	}
	if a.has("timeout") {
		body["timeout"] = fmt.Sprintf("%ds", a.number("timeout"))
	}
	e := c.withMachineLease(ctx, cred, a.text("app"), a.text("id"), func(x context.Context, n string) error {
		h := http.Header{}
		h.Set(leaseHeader, n)
		if err := c.machinesRequestHeaders(x, cred, http.MethodPost, machinePath(a.text("app"), a.text("id"))+"/stop", body, nil, h); err != nil {
			return err
		}
		t := time.Duration(a.number("wait-timeout")) * time.Second
		if t == 0 {
			t = 5 * time.Minute
		}
		return c.waitMachineState(x, cred, a.text("app"), a.text("id"), "stopped", t)
	})
	if e != nil {
		return nil, e
	}
	return map[string]string{"status": "stopped"}, e
}
func (c *flyClient) machineRestart(ctx context.Context, cred string, a toolArguments) (any, error) {
	q := url.Values{}
	q.Set("force_stop", strconv.FormatBool(a.flag("force")))
	if a.has("time") {
		q.Set("timeout", fmt.Sprintf("%ds", a.number("time")))
	}
	if a.has("signal") {
		q.Set("signal", a.text("signal"))
	}
	p := machinePath(a.text("app"), a.text("id")) + "/restart?" + q.Encode()
	e := c.withMachineLease(ctx, cred, a.text("app"), a.text("id"), func(x context.Context, n string) error {
		h := http.Header{}
		h.Set(leaseHeader, n)
		if err := c.machinesRequestHeaders(x, cred, http.MethodPost, p, nil, nil, h); err != nil {
			return err
		}
		if a.flag("skip-health-checks") {
			return nil
		}
		t := time.Duration(a.number("wait-timeout")) * time.Second
		if t == 0 {
			t = 5 * time.Minute
		}
		return c.waitMachineHealthy(x, cred, a.text("app"), a.text("id"), t)
	})
	if e != nil {
		return nil, e
	}
	return map[string]string{"status": "restarted"}, e
}
func (c *flyClient) machineDestroy(ctx context.Context, cred string, a toolArguments) (any, error) {
	p := machinePath(a.text("app"), a.text("id"))
	if a.flag("force") {
		p += "?kill=true"
	}
	e := c.withMachineLease(ctx, cred, a.text("app"), a.text("id"), func(x context.Context, n string) error {
		h := http.Header{}
		h.Set(leaseHeader, n)
		return c.machinesRequestHeaders(x, cred, http.MethodDelete, p, nil, nil, h)
	})
	if e != nil {
		return nil, e
	}
	return map[string]string{"status": "destroyed"}, e
}
func (c *flyClient) machineLeaseView(ctx context.Context, cred string, a toolArguments) (any, error) {
	var out fly.MachineLease
	e := c.machinesRequest(ctx, cred, http.MethodGet, machinePath(a.text("app"), a.text("id"))+"/lease", nil, &out)
	return &out, e
}
func (c *flyClient) machineLeaseClear(ctx context.Context, cred string, a toolArguments) (any, error) {
	var lease fly.MachineLease
	p := machinePath(a.text("app"), a.text("id")) + "/lease"
	e := c.machinesRequest(ctx, cred, http.MethodGet, p, nil, &lease)
	if e == nil {
		if lease.Data == nil || lease.Data.Nonce == "" {
			return nil, errors.New("Fly returned an invalid machine lease")
		}
		h := http.Header{}
		h.Set(leaseHeader, lease.Data.Nonce)
		e = c.machinesRequestHeaders(ctx, cred, http.MethodDelete, p, nil, nil, h)
	}
	if e != nil {
		return nil, e
	}
	return map[string]string{"status": "cleared"}, e
}
func (c *flyClient) machineEgress(op string) nativeToolHandler {
	return func(ctx context.Context, cred string, a toolArguments) (any, error) {
		auth, _, _, e := flyHeaders(cred)
		if e != nil {
			return nil, e
		}
		app, id := a.text("app"), a.text("id")
		if op == "list" {
			var d struct {
				App *struct {
					Machines struct {
						Nodes []struct {
							ID     string `json:"id"`
							Egress struct {
								Nodes []map[string]any `json:"nodes"`
							} `json:"egressIpAddresses"`
						} `json:"nodes"`
					} `json:"machines"`
				} `json:"app"`
			}
			e = c.graphql(ctx, "machine_egress_list", auth, `query($appName:String!){app(name:$appName){machines{nodes{id egressIpAddresses{nodes{id ip version region updatedAt}}}}}}`, map[string]any{"appName": app}, &d)
			if e != nil {
				return nil, e
			}
			if d.App == nil {
				return nil, errors.New("Fly omitted the app from the egress IP response")
			}
			for _, m := range d.App.Machines.Nodes {
				if m.ID == id {
					return m.Egress.Nodes, nil
				}
			}
			return []map[string]any{}, nil
		}
		field := "allocateEgressIpAddress"
		if op == "release" {
			field = "releaseEgressIpAddress"
		}
		var d map[string]any
		e = c.graphql(ctx, "machine_egress_"+op, auth, fmt.Sprintf(`mutation($input:%sEgressIPAddressInput!){%s(input:$input){v4 v6}}`, strings.Title(op), field), map[string]any{"input": map[string]any{"appId": app, "machineId": id}}, &d)
		if e == nil && d[field] == nil {
			e = errors.New("Fly omitted the egress IP mutation result")
		}
		return d, e
	}
}

func (c *flyClient) withMachineLease(ctx context.Context, credential, app, id string, fn func(context.Context, string) error) error {
	op, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var lease fly.MachineLease
	if e := c.machinesRequest(op, credential, http.MethodPost, machinePath(app, id)+"/lease?ttl=270", nil, &lease); e != nil {
		return fmt.Errorf("could not acquire machine lease: %w", e)
	}
	if lease.Data == nil || lease.Data.Nonce == "" {
		return errors.New("Fly returned an invalid machine lease")
	}
	runErr := fn(op, lease.Data.Nonce)
	cleanup, cc := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cc()
	h := http.Header{}
	h.Set(leaseHeader, lease.Data.Nonce)
	releaseErr := c.machinesRequestHeaders(cleanup, credential, http.MethodDelete, machinePath(app, id)+"/lease", nil, nil, h)
	if releaseErr != nil && httpStatus(releaseErr) == http.StatusNotFound {
		// A successful destroy removes the lease endpoint with the Machine.
		if _, getErr := c.getMachine(cleanup, credential, app, id); httpStatus(getErr) == http.StatusNotFound {
			releaseErr = nil
		}
	}
	if runErr != nil && releaseErr != nil {
		return errors.Join(runErr, fmt.Errorf("machine lease release also failed: %w", releaseErr))
	}
	if runErr != nil {
		return runErr
	}
	if releaseErr != nil {
		return fmt.Errorf("operation succeeded but machine lease release failed: %w", releaseErr)
	}
	return nil
}

func (c *flyClient) waitMachineHealthy(ctx context.Context, credential, app, id string, timeout time.Duration) error {
	if timeout <= 0 || timeout > 4*time.Minute {
		timeout = 4 * time.Minute
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		m, e := c.getMachine(wctx, credential, app, id)
		if e != nil {
			return e
		}
		healthy := m.State == "started"
		for _, check := range m.Checks {
			if check == nil || string(check.Status) != "passing" {
				healthy = false
				break
			}
		}
		if healthy {
			return nil
		}
		select {
		case <-wctx.Done():
			return errors.New("timed out waiting for machine health")
		case <-tick.C:
		}
	}
}
func (c *flyClient) waitMachineState(ctx context.Context, credential, app, id, state string, timeout time.Duration) error {
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		m, e := c.getMachine(wctx, credential, app, id)
		if e != nil {
			return e
		}
		if m.State == state {
			return nil
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("timed out waiting for machine state %s", state)
		case <-tick.C:
		}
	}
}
