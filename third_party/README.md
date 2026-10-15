# Fly API reuse

`internal/gateway/tool_catalog.json` contains only MCP descriptions and argument
definitions from [superfly/flyctl at 95b7f3e777a4c685599b6b75cfcfc0d8cbbd9fd9](https://github.com/superfly/flyctl/tree/95b7f3e777a4c685599b6b75cfcfc0d8cbbd9fd9/internal/command/mcp/server).
Copyright Fly.io contributors; licensed under Apache-2.0 (see `flyctl.LICENSE`).
Its CLI builders are not copied, imported, built, or executed.

Regenerate from that revision with:

```sh
go run scripts/generate-tool-catalog.go /path/to/flyctl/internal/command/mcp/server
```

The gateway adapts this metadata for hosted use: an explicit app is required,
unknown arguments are rejected, numbers are bounded integers, and write/read
annotations describe the native operation. Defaults are applied by handlers,
not blindly to updates where omitted fields must be preserved.

Native handlers reuse exported models from `github.com/superfly/fly-go v0.11.2`
and use its API methods as protocol references. They do not instantiate its
HTTP clients, which retry some mutations and use ambient endpoint overrides.
