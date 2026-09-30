# pd-mcp — ProjectDiscovery MCP Server (estate-hardened fork)

Fork of `intelligent-ears/pd-tools-mcp` (MIT), adapted for the toxicwind estate.

## What changed from upstream

- **Estate binary resolution** — `src/tools/runner.ts` resolves binaries from
  `PD_TOOLS_DIR` (default `/home/toxic/.pdtm/go/bin`) and `SHUFFLEDNS_BIN`
  (default `/home/toxic/go/bin/shuffledns`), with per-binary override
  `PD_<NAME>_BIN` (e.g. `PD_HTTPX_BIN`).
- **No-shell spawns with timeouts** — every executor goes through a shared
  timeout-guarded runner (subfinder/dnsx/httpx/tlsx: 5 min, katana/naabu/
  shuffledns: 10 min, nuclei: 15 min). No more hanging the MCP client.
- **Input validation** — domains/hosts/ports are validated and capped at the
  tool boundary; all stdin payloads are deduplicated and newline-stripped.
- **New tools**: `tlsx` (TLS probing) and `shuffledns` (active subdomain
  brute-force with a wordlist).
- **naabu**: `scanType` param — `"c"` connect scan (unprivileged default),
  `"s"` SYN scan (needs CAP_NET_RAW).
- **nuclei**: template selection via `-id` (template IDs), `-duc` always on,
  non-zero exits from findings no longer reported as errors.
- **httpx**: replaced the headless-chrome `screenshot` flag with `techDetect`
  (wappalyzer).
- Kept upstream's `bug_bounty_workflow` composite tool (now timeout-safe).

## Tools

| tool | binary |
|---|---|
| subfinder | subfinder |
| dnsx | dnsx |
| naabu | naabu |
| httpx | httpx |
| katana | katana |
| nuclei | nuclei |
| tlsx | tlsx |
| shuffledns | shuffledns |
| bug_bounty_workflow | composite |

## Run

```bash
bun install
bun src/index.ts        # stdio MCP server
```

## Verify

```bash
bun driver.ts           # tools/list + one live tools/call per binary
```

## License

MIT (upstream `intelligent-ears/pd-tools-mcp`).
