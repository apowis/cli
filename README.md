<p align="center">
    <img src="/logo-cli.png" align="center" alt="VulnCheck Logo" width="150" />
</p>

# The VulnCheck CLI
`vulncheck` is access to the VulnCheck API on the command line. It brings index browsing, backup management, and vulnerability scanning to the terminal.

<p align="center">
    <img src="/vulncheck-scan.gif" />
</p>

[![Release](https://img.shields.io/github/v/release/vulncheck-oss/cli)](https://github.com/vulncheck-oss/cli/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/vulncheck-oss/cli.svg)](https://pkg.go.dev/github.com/vulncheck-oss/cli)
[![Lint](https://github.com/vulncheck-oss/cli/actions/workflows/lint.yml/badge.svg)](https://github.com/vulncheck-oss/cli/actions/workflows/lint.yml)
[![Tests](https://github.com/vulncheck-oss/cli/actions/workflows/test.yml/badge.svg)](https://github.com/vulncheck-oss/cli/actions/workflows/test.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vulncheck-oss/cli/pulls)

## Installation 

### Provided install scripts

You can easily install vulncheck using an install script. Choose the script and method that matches your operating system:

### macOS and Linux

Open a terminal and run:

```bash
curl -sSL https://raw.githubusercontent.com/vulncheck-oss/cli/main/install.sh | bash
```

This will prompt you to choose between system-wide installation (requires sudo) or local user installation.

> [!NOTE]
> The install script also supports non-interactive installation options:
> - `--sudo` for system-wide installation without prompts
> - `--non-sudo` for local user installation without prompts
> - `--help` or `-h` to see all available options
> ```bash
> curl -sSL https://raw.githubusercontent.com/vulncheck-oss/cli/main/install.sh | bash -s -- --help
> ```

### Windows

Open PowerShell and run:

```
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/vulncheck-oss/cli/main/install.ps1'))
```

To enable tab completion, dot-source the bundled script from your PowerShell profile:

```powershell
Add-Content -Path $PROFILE -Value ". '$env:LOCALAPPDATA\Programs\vulncheck\share\powershell\vulncheck.ps1'"
```

`vulncheck` binaries are also available for MacOS, Linux, and Windows. You can download precompiled binaries from our [releases page](https://github.com/vulncheck-oss/cli/releases/latest)

### Verify the installation

Once installed, confirm the binary prints the desired version:

```bash
vulncheck version
```

You should see the version, build date, and changelog URL. If you get "command not found", reopen your shell so the new `PATH` is picked up, then try again.

## Configuration
* Run `vulncheck auth login` to authenticate with your VulnCheck account.
* Alternatively `vulncheck` will respect the `VULNCHECK_API_TOKEN` environment
  variable — the same name used by the VulnCheck SDKs and MCP server. The
  legacy `VC_TOKEN` also still works, and **takes precedence when both are
  set**.
* `vulncheck auth` by itself will show other options like checking your status and logging out.

Either environment variable wins over the saved config file. Because of that,
`auth login` and `auth logout` refuse while one is set — otherwise they would
report success having changed nothing that takes effect. Run `vulncheck auth
status` to see which source, and which variable, the active token came from.


## Agentic / scripted usage

The CLI is designed to be safe to drive from scripts and AI agents. This section is the contract — the surfaces below are intended to remain stable across releases (additions are not breaking changes; renames / removals are).

### Global flags

| Flag                | Effect |
|---------------------|--------|
| `--json`            | Emit JSON on stdout; route info/progress lines to stderr; errors emitted as a structured envelope. |
| `--quiet`           | Suppress informational output. Errors and payloads still render. |
| `--no-color`        | Disable ANSI styling. Also honours the `NO_COLOR` env var. |
| `--no-interactive` | Refuse to block on TUI prompts; commands that need a prompt return an error instead. Implied by `--json`, non-TTY stdin/stdout, and any of the `CI` / `BUILD_NUMBER` / `RUN_ID` env vars. |

### Environment variables

| Variable                                   | Effect |
|--------------------------------------------|--------|
| `VULNCHECK_API_TOKEN`                      | API token, and the recommended name — shared with the VulnCheck SDKs and MCP server. Takes precedence over `~/.config/vulncheck/vulncheck.yaml`; while set, `auth login` and `auth logout` refuse rather than writing a file that would be ignored. |
| `VC_TOKEN`                                 | Legacy alias, still fully supported and **taking precedence over `VULNCHECK_API_TOKEN` when both are set**, so no existing setup changes credential. Clear both to fall back to the config file. `auth status` reports which is in use. |
| `NO_COLOR`                                 | Any non-empty value disables ANSI styling. |
| `CI` / `BUILD_NUMBER` / `RUN_ID`           | Any of these set implies non-interactive mode (no prompts). |
| `VC_TI_PROJECT`                            | GCP billing project for `target-intel` (flag `--project` wins; then this; then the `targetintel.project` saved by `target-intel auth login`; default `viewport-473910`). |
| `VC_TI_LOCATION`                           | BigQuery location for `target-intel` (default `europe-west1`). Same precedence as the project. |
| `VC_TI_VIEWS_DATASET`                      | Dataset holding the `observations_by_*` routines used by `target-intel cves` and `product` (default `anchorbreaker_views_prod`). Same precedence as the project. |
| `VC_TI_DATASET`                            | Dataset holding the warehouse tables read by `target-intel host` and `cves --counts` (default `anchorbreaker_prod`). Same precedence as the project. |
| `VC_TI_CREDENTIALS`                        | Path to a Google credentials JSON file (service-account key or `authorized_user`). Takes precedence over the stored `target-intel auth login` credential and Application Default Credentials; while set, `target-intel auth login` refuses. |
| `VC_TI_MAX_COST`                           | Default per-query cost cap in USD for `target-intel` queries, enforced by BigQuery as a bytes-billed limit (flag `--max-cost` wins; built-in default `1.00`; `0` disables the cap). |
| `VC_TI_PRICE_PER_TIB`                      | On-demand price used to turn bytes into dollars (default `6.25`). |

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success. |
| 1    | Generic / internal error. |
| 2    | Validation failure (bad args, missing required flag, malformed request). |
| 3    | Auth failure (no token, or the server rejected the token). |
| 4    | Resource not found (HTTP 404, no such index). |
| 5    | Rate limited (HTTP 429). |
| 6    | Network failure (DNS, connection refused, timeout). |
| 7    | Cost limit exceeded (BigQuery stopped a `target-intel` query at the bytes-billed cap before anything was billed). |
| 130  | Cancelled by SIGINT (POSIX `128 + 2`). |

### Error envelope

In `--json` mode, errors are emitted to **stdout** as:

```json
{
  "schema_version": 1,
  "error": {
    "code": "auth_required",
    "message": "...",
    "http_status": 401,
    "hint": "..."
  }
}
```

`code` is one of: `internal`, `validation`, `auth_required`, `auth_invalid`, `not_found`, `rate_limited`, `network`, `bad_request`, `cost_limit_exceeded`, `cancelled`. `http_status` is omitted for non-HTTP errors. `hint` is optional remediation context, present only when the message alone isn't actionable (e.g. naming the variable that supplied a rejected token). Rendered on stderr as `hint: ...` outside `--json` mode.

### Probe commands

Use these to inspect the CLI itself before dispatching work:

```bash
vulncheck version --json
# {"schema_version": 1, "version": "...", "build_date": "...", "changelog_url": "..."}

vulncheck auth status --json
# {"schema_version": 1, "authenticated": true, "token_source": "env",
#  "token_env_var": "VC_TOKEN", "user": "...", "email": "..."}
# Exit 0 even when authenticated=false — agents dispatch on the bool.
# token_env_var names which variable supplied the token when token_source is
# "env"; omitted otherwise. Set when authenticated=false too, so a rejected
# token can be traced to the variable holding it.
# token_shadowed: true is added when an environment token is overriding a
# *different* token saved in vulncheck.yaml — the usual cause of "I logged
# in but nothing changed". Omitted otherwise, so the CI shape (env token
# only, no config file) never reports shadowing.

vulncheck commands
# {"schema_version": 1, "root": {"name":"vulncheck", "subcommands":[...]}, ...}
# Machine-readable dump of the whole command tree — every subcommand,
# every flag (with type + default + usage), aliases, deprecation. Use
# this instead of parsing --help. Auth is not required.
```

### Pagination

```bash
vulncheck token list --json --limit 10 --page 2
vulncheck token list --json --all       # auto-paginate, single combined array
vulncheck index list <index> --json --all
```

### Batch input

`purl`, `cpe`, `tag`, `pdns` accept multiple inputs via positional args, stdin (when piped), or `--from-file <path>`. Blank lines and `#`-prefixed comments in the file are ignored. Batch mode requires `--json`.

```bash
# Stdin
cat purls.txt | vulncheck purl --json

# File
vulncheck cpe --from-file ./cpes.txt --json
```

The batch envelope is a stable array, one row per input, in input order:

```json
[
  {"input": "pkg:npm/lodash@4.0.0", "data": { ... }},
  {"input": "pkg:bad/string", "error": "no result returned for this purl"}
]
```

### Cancellation

`SIGINT` / `SIGTERM` cancel in-flight HTTP requests cleanly via context propagation. Long-running ops (`scan`, `offline sync`, `backup download`) honour cancellation; partial files are removed on the way out where applicable.

### JSON output discipline

When `--json` is set:
- stdout carries **only** the JSON payload (or the error envelope above).
- stderr carries every info line, progress bar, spinner, prompt, and warning.
- TUI elements (bubbletea, huh prompts) are automatically suppressed.

This means `vulncheck <cmd> --json | jq` always works — no `tail`/`sed` cleanup needed.


## Available commands

Every command below accepts the [global flags](#global-flags) (`--json`, `--quiet`, `--no-color`, `--no-interactive`, `--help`/`-h`). Per-command flag tables list only what is specific to that command.

- [`auth`](#auth) — log in / out, check status
- [`token`](#token) — API token management
- [`indices`](#indices) — list or browse the catalogue of indices
- [`index`](#index) — query one index
- [`advisory`](#advisory) — query v4 advisories in CVE Record Format 5.2
- [`nvd`](#nvd) — query the NVD API 2.0 compatible endpoints
- [`backup`](#backup) — download or fetch a signed URL for an index or advisory-feed backup
- [`cpe`](#cpe) — look up CVEs for a CPE (single or batch)
- [`purl`](#purl) — look up CVEs for a PURL (single or batch)
- [`tag`](#tag) — look up IP-intelligence tag membership
- [`pdns`](#pdns) — look up passive-DNS list membership
- [`rule`](#rule) — look up initial-access-intelligence rules
- [`scan`](#scan) — scan a directory (SBOM + vulnerability lookup)
- [`offline`](#offline) — sync indices locally and query them without hitting the API
- [`target-intel`](#target-intel) — query Target Intelligence scan data in BigQuery under a cost cap
- [`version`](#version) — print the CLI version
- [`upgrade`](#upgrade) — update the CLI in place


### auth

```
vulncheck auth login
vulncheck auth logout
vulncheck auth status [--json]
```

`login` walks you through a browser or paste-token flow — refuses when `--no-interactive`. `status --json` calls `/me` to actually verify the token; the payload always has `.authenticated: bool` and exits `0` regardless (see [Probe commands](#probe-commands)).


### token

```
vulncheck token list [--limit N] [--page N] [--all]
vulncheck token create <label>
vulncheck token remove <id>
vulncheck token browse
```

`list --json --all` auto-paginates and returns one combined JSON array.

`create --json` returns `{schema_version, id, label, token_on_stderr: true}` and prints the actual secret on a single line to **stderr**. That way a pipeline like `vulncheck token create ci-runner --json > token.json` never captures the secret in the JSON file. Pass `--allow-token-on-stdout` if you want the token embedded in the JSON payload instead (`{... "token": "vc_..."}`) — you're taking responsibility for the redirection.

`browse` is interactive; it refuses with exit `2` under `--no-interactive`.


### indices

```
vulncheck indices list [<search>]
vulncheck indices browse [<search>]
```

Lists (or interactively browses) the catalogue of available indices. `list` accepts a fuzzy search term.


### index

```
vulncheck index list <index> [--full] [--all] [query flags]
vulncheck index browse <index> [query flags]
```

`list --all` walks `next_cursor` end-to-end and emits one combined array. `browse` runs an interactive viewport; under `--json` (or `--no-interactive`) it falls back to `list` output. Query flags come from the index's schema (`--cve`, `--alias`, `--limit`, `--cursor`, etc.); see the [API docs](https://docs.vulncheck.com/api/indice) for the full set.


### advisory

```
vulncheck advisory feeds [search]                      # GET /v4/advisory/list
vulncheck advisory list [--full] [--all] [query flags] # GET /v4/advisory
vulncheck advisory browse [--full] [query flags]
```

Every record is CVE Record Format 5.2, and there is one record per feed per CVE.

At least one filter is required; see `advisory list --help` for the set (`--feed`, `--cve`, `--vendor`, `--purl`, `--updated-after`, …) and `advisory feeds` for `--feed` values. `--limit` caps at 100 and `--page × --limit` at 10,000 — page past that with `--start-cursor` and `--cursor`, or `--all` to walk it in one call (which buffers every record, so prefer cursors on the largest feeds). `browse` runs an interactive viewport.


### nvd

```
vulncheck nvd cves       [--full] [query flags]   # GET /rest/json/cves/2.0
vulncheck nvd cvehistory [--full] [query flags]   # GET /rest/json/cvehistory/2.0
vulncheck nvd cpes       [--full] [query flags]   # GET /rest/json/cpes/2.0
vulncheck nvd cpematch   [--full] [query flags]   # GET /rest/json/cpematch/2.0
vulncheck nvd source     [--full] [query flags]   # GET /rest/json/source/2.0
```

These mirror the NVD API 2.0: each flag is an NVD query parameter in kebab-case (`--cve-id` is `cveId`, `--last-mod-start-date` is `lastModStartDate`), its value is sent unchanged, and the API validates it. They work with any VulnCheck API token, including community. Output is the endpoint's records (`vulnerabilities`, `cveChanges`, `products`, `matchStrings` or `sources`); `--full` returns the whole NVD response. Each command makes one request: to page, pass `--cursor ""` for the first page and then each response's `nextCursor`, or `--start-index` (the only paging on `source`).

```bash
vulncheck nvd cves --cve-id CVE-2021-44228 --json
vulncheck nvd cves --has-kev --results-per-page 100 --cursor "" --full --json
vulncheck nvd cvehistory --event-name "CVE Modified" --change-start-date 2026-09-01T00:00:00.000 --change-end-date 2026-10-01T00:00:00.000 --json
```

### backup

```
vulncheck backup list                       # indices with a backup available
vulncheck backup url <index>                # signed temporary URL only
vulncheck backup download <index>           # download the archive

vulncheck backup advisory list              # GET /v4/backup
vulncheck backup advisory url <feed>        # GET /v4/backup/{feed}
vulncheck backup advisory download <feed>
```

`download` picks the bubbletea progress bar for TTYs and a plain SIGINT-safe streaming download (writing to `<name>.part` and renaming on success) for headless callers. `url --json` returns `{filename, sha256, date_added, url}`.

The `advisory` subcommands are a **different corpus, not a newer version** of the same archives, and most feed names are also index names — so the same argument usually addresses both. A v3 zip holds that feed's native records — for `sigmahq-sigma-rules` that includes the Sigma rule itself and its ATT&CK techniques — while the v4 zip holds CVE 5.2 records, one per CVE, dropping both those fields and every advisory with no CVE attached. A feed whose advisories are mostly not CVE-keyed can shrink to a fraction of its v3 record count. The v4 archive is a single `<feed>.jsonl` inside the zip, and its lists are parquet-shaped (`{"list":[{"element":…}]}`), so it is **not** a bulk copy of `advisory list --json`. The v4 object key carries no timestamp, so repeat downloads overwrite rather than accumulate — the command warns when it does. `url`/`download --json` carry `corpus` and `format` fields, because a bare `abbott.zip` on disk records nothing about which corpus produced it, and a `url` field so `jq -r .url` works against both.


### cpe

```
vulncheck cpe <cpe>
vulncheck cpe --from-file cpes.txt --json
echo cpe:2.3:… | vulncheck cpe --json
```

Batch mode (multiple positional args, `--from-file`, or piped stdin) requires `--json` and returns the [stable batch envelope](#batch-input).


### purl

```
vulncheck purl <purl>
vulncheck purl --from-file purls.txt --json
```

Same batch semantics as `cpe`. Batch requests are sent as a single `/v3/purls` POST rather than N GETs.


### tag

```
vulncheck tag <tag-name>
vulncheck tag --from-file tags.txt --json
```

Returns the newline-split list of matches for the given IP-intelligence tag. Batch input supported.


### pdns

```
vulncheck pdns <list-name>
vulncheck pdns --from-file lists.txt --json
```

Passive-DNS list membership. Batch input supported.


### rule

```
vulncheck rule <rule-name> [--table]
```

Look up an initial-access-intelligence rule. `--table` renders single-column table output; `--json` (global) supersedes.


### scan

```
vulncheck scan <path> [flags]
vulncheck scan --sbom-input-file <file> --json
```

Generates an SBOM for `<path>`, extracts PURLs, then either calls the vulncheck API (default) or queries local offline indices.

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Save results to a file. |
| `-n`, `--file-name` | Custom output filename (default `output.json`). |
| `-o`, `--sbom-output-file` | Save the generated SBOM to a file. |
| `-i`, `--sbom-input-file` | Load an existing SBOM instead of generating one. |
| `-s`, `--sbom-only` | Generate the SBOM without running the vuln lookup. |
| `-c`, `--include-cpes` | Extract CPEs as well as PURLs (offline mode only, for now). |
| `--offline` | Use locally-synced indices instead of the API. |
| `--offline-meta` | Populate metadata (CVSS, KEV, description) from `vulncheck-nvd2` in offline mode. |
| `--warn-on-index` | Warn instead of failing when a required offline index isn't cached. |
| `--disable-ui` | Alias for `--no-interactive` (kept for backwards compatibility). |
| `--enrich` | Enrich the generated SBOM with metadata from `proxy.golang.org` / Maven Central / NPM / PyPI. Comma-separated scopes: `all`, `golang`, `java`, `javascript`, `python`; prefix with `-` to exclude (e.g. `all,-java`). Off by default; requires network — cannot be combined with `--offline` or `--sbom-input-file`. |

The progress TUI is auto-suppressed whenever the renderer can't safely draw it (`--json`, `--no-interactive`, non-TTY, CI).


### offline

```
vulncheck offline sync   [--add <name>|--remove <name>|--purge|--force|--choose] [--json]
vulncheck offline status [--json]
vulncheck offline purl   <purl> [--json]
vulncheck offline cpe    <cpe>  [--json] [--stats]
vulncheck offline ipintel <3d|10d|30d> [--country=...] [--asn=...] [--cidr=...] [--json]
```

Local queries against synced indices. `sync --json` returns `{schema_version, action, selected, elapsed_seconds}`; `status --json` returns the cached-index array. Under `--no-interactive` the sync command refuses without an explicit `--add` / `--remove` / `--purge` (no picker prompt).


### target-intel

Alias: `ti`. Queries VulnCheck Target Intelligence scan data in BigQuery. Authentication is to Google, not the VulnCheck API, so these commands do not need `VULNCHECK_API_TOKEN`.

```
vulncheck target-intel auth login   [--no-browser] [--project <id>] [--location <loc>] [--json]
vulncheck target-intel auth logout  [--json]
vulncheck target-intel auth status  [--json]
vulncheck target-intel datasets list [--json]
vulncheck target-intel tables list <dataset> [--json]
vulncheck target-intel tables describe <dataset>.<table> [--json]
vulncheck target-intel estimate [--query <sql> | --from-file <path>] [--max-cost <usd>] [--json]
vulncheck target-intel query    [--query <sql> | --from-file <path>] [--limit <n>|--all] [--max-cost <usd>] [--dry-run] [--no-cache] [--timeout <d>] [--json]
vulncheck target-intel cves     --cves <id>[,<id>...] [--days <n>] [--min-confidence <10|20|30|40>] [--group-by <country|asn|product|version> | --counts] [--limit <n>|--all] [--max-cost <usd>] [--dry-run] [--json]
vulncheck target-intel cves     --top [--kev] [--min-epss <0-1>] [--limit <n>|--all] [--json]
vulncheck target-intel product  [--vendor <pattern>] [--product <pattern>] [--days <n>] [--group-by <country|asn|product|version>] [--limit <n>|--all] [--max-cost <usd>] [--dry-run] [--json]
vulncheck target-intel host     <ipv4|cidr> [--days <n>] [--limit <n>|--all] [--max-cost <usd>] [--dry-run] [--json]
vulncheck target-intel service http [--title <pattern>] [--server <pattern>] [--status <code>] [--favicon <hash>] [--body-hash <sha256>] [--snapshot-hash <hash>] [--days <n>] [--limit <n>|--all] [--max-cost <usd>] [--dry-run] [--json]
```

`auth login` runs the same browser flow as `gcloud auth login` (loopback redirect, PKCE) and stores a refresh token in `~/.config/vulncheck/target-intel-credentials.json` (mode 0600, Google `authorized_user` format). It also saves the billing project and location to `vulncheck.yaml` so later invocations need no flags. Credential precedence: `VC_TI_CREDENTIALS`, then the stored login, then Application Default Credentials. `auth status --json` always exits 0 and returns `{schema_version, authenticated, credential_source, principal, project, project_source, location, location_source, max_cost_usd, reason}`.

Every `query` runs with `--max-cost` (default $1.00) sent to BigQuery as `maximumBytesBilled`. BigQuery enforces that cap on the bytes actually read: a job that would bill more **fails before anything is charged**, and the command exits 7 with error code `cost_limit_exceeded` and a hint naming the `--max-cost` value that would allow it. There is no dry run on the normal path: BigQuery's estimate is an upper bound that cannot see cluster pruning, so a lookup on a clustered table (every `observations_by_*` routine, `host`, `cves --counts`) can estimate hundreds of GiB and bill a few. `estimate` and `--dry-run` still return that free estimate on request and warn when it is over the cap. Only a single `SELECT` (or `WITH ... SELECT`) statement is accepted; the check is a client-side statement guard, and the credential's own BigQuery permissions remain the real boundary. `--limit` caps rows returned, not bytes scanned: put `WHERE`/`LIMIT` in the SQL to cut cost. SQL comes from `--query`, `--from-file` (`-` for stdin), or piped stdin.

`query --json` returns `{schema_version, job_id, bytes_billed, cost_usd, cache_hit, total_rows, returned_rows, truncated, schema: [{name, type, mode}], rows: [{...}]}`. Timestamps are RFC 3339, `BYTES` columns are base64, `NUMERIC` values are decimal strings. `estimate --json` (and `query --dry-run --json`) returns `{schema_version, estimate, max_cost_usd, within_limit}`. `tables describe --json` returns the schema plus size, row count, partition and clustering keys and the cost of a full scan; it is free, so use it before writing SQL.

`cves` wraps the `observations_by_cves_scored` routine: hosts seen in the last `--days` (default 30) whose fingerprint matches any of the CVEs at or above `--min-confidence` (default 20; 30 and 40 are confirmed, 10 adds versionless product matches). Pass every CVE in one call rather than one call each: the routine scans its inputs once however many are given. Tiers 20 and above read a nightly match snapshot: the dry run estimates about 20 GiB ($0.12) and the bill is usually a third of that, because the snapshot is clustered on CVE. Tier 10, and any CVE whose NVD mapping changed since the snapshot was built, are matched live and scan more, so `--dry-run` first when in doubt. The same `--max-cost` cap applies. Text mode shows a compact column set; `--json` returns the `query` payload shape plus `routine` and the echoed `query: {cves, min_confidence, lookback_days}`, with every column the routine returns (`matched_cve_id`, `ip`, `port`, `service`, `cpe`, `vendor`, `product`, `version`, `confidence`, `vulnerable_cves`, `epss_*`, `kev_*`, `country`, `asn`, `as_name`, `backpatched`, ...). The routines live in `anchorbreaker_views_prod` by default; override with `--views-dataset` or `VC_TI_VIEWS_DATASET`.

`cves --group-by <key>` and `product --group-by <key>` wrap the routine call in a rollup: one row per `country`, `asn`, `product` or `version` with `hosts` (`COUNT(DISTINCT ip_int)`, since routine output has one row per observation and a plain row count overstates hosts) and `observations`, largest first; a multi-CVE call groups per `matched_cve_id` too. The JSON adds `group_by` to the `cves`/`product` payload. `cves --counts` skips the routine and reads the nightly `cve_host_counts` table instead (a point lookup, well under 1 MiB billed): per CVE, hosts over the last 30 days split by tier (`hosts_40`, `hosts_30`, `hosts_20`, `hosts_10`, `hosts_confirmed` = 40 + 30), the KEV and EPSS signals and `top_countries`. A CVE with no row is named in `missing` (JSON) or a warning (text); it was matched on no host at any tier, which is not the same as zero hosts for a product the tiers cannot discriminate. `cves --top` reads the same table as a leaderboard, every CVE with a version-level match ordered by `hosts`, with `--kev` (VulnCheck KEV only) and `--min-epss` filters; `--limit` (default 100) caps the rows and `total_rows` is the number of CVEs that matched the filters. JSON carries `table`, `query: {kev_only, min_epss}` and the same columns as `--counts`.

`product` wraps `observations_by_product`: hosts seen in the last `--days` whose fingerprint matches `--vendor` and/or `--product` (case-insensitive substring; pass `%` for an explicit LIKE pattern; the vendor pattern is also matched against the product name). At least one is required. A 30-day call dry-runs at about 63 GiB ($0.38) and bills what it estimates; `--group-by` reads fewer columns, about 36 GiB ($0.22). JSON is the `query` payload shape plus `routine` and `query: {vendor, product, lookback_days}`.

`host <ipv4>` answers "what is this host running" with three point reads of tables clustered on the host, together about 1 GiB billed (under a cent): `host_profile` (ports and protocols seen listening in the current scan window, joined to geolocation and ASN), `fingerprint_current` (every product identified in the host's latest scan of each port within `--days`, with CPE, rule and the rule-annotated CVEs) and `cpe_cve_matches` (the CVEs each port's CPEs map to, about 90 MB). Ports are those observed listening, bounded by what was probed: an absent port is "not seen listening", never "closed". CVEs are scored on the `cves` tier scale, highest per port and CVE: 40 for a rule annotation on a versioned fingerprint whose probe succeeded, 30 for any other rule annotation or an unpatched-looking version match, 20 for a version match a distro may have backported, 10 for a versionless product match; only ports fingerprinted within `--days` are scored, and `--min-confidence` (default 20; single IP only) drops lower tiers. `cpe_cve_matches` also matches CPE aliases, so a host can list a CVE that `cves` does not return for it. `--json` returns `{schema_version, query: {ip, lookback_days, min_confidence}, found, profile, fingerprints: [...], cves: [{port, cve_id, confidence, match, cpe}], cves_below_min_confidence, jobs: [{name, job_id, bytes_billed, cost_usd, cache_hit}]}`; `profile` is `null` when the host has no profile row. IPv4 only. A CIDR argument (`/16` or longer; wider is refused) returns an inventory instead: one row per host seen listening in the range, in address order, with `country_code`, `asn`, `as_name`, `last_seen`, `port_count`, `services` (`port/transport service`) and `products` (distinct `vendor product version` strings identified within `--days`). Both tables are clustered on the host, so the range filter prunes: a `/16` with about 6,000 live hosts billed 0.4 GiB in 3 seconds. `--limit` (default 100) caps the hosts returned; `--json` is the `query` payload shape plus `query: {cidr, lookback_days}`. These tables live in `anchorbreaker_prod` by default; override with `--dataset` or `VC_TI_DATASET`.

`service http` lists distinct HTTP configurations rather than hosts: it reads `http_snapshot`, one row per distinct response, for those last seen within `--days` (default 30, at most 365) that match every filter given, and returns `snapshot_hash`, `title`, `server`, `status_code`, `content_length`, `favicon_shodan_hash`, `body_sha_256`, `first_seen` and `last_seen`, newest first. At least one of `--title`, `--server` (case-insensitive substring, `%` for an explicit LIKE pattern), `--favicon`, `--body-hash` or `--snapshot-hash` is required; `--status` (100 to 599) only narrows beside one of them, since on its own it matches hundreds of millions of responses. `--favicon` picks its column by shape: a decimal integer is the Shodan (mmh3) hash, 32 hex characters MD5, 64 hex characters SHA-256. The body, headers, `robots_txt` and `security_txt` are never read, nor is `http_parsed`, whose body column bills about 1.7 TiB ($10) for 30 days: a 30-day search dry-runs at 49 GiB ($0.30) whatever the filters, and a `--snapshot-hash` lookup bills a few MiB because the table is clustered on it. Unlike the other commands, `--limit` (default 100) is a `LIMIT` in the SQL, so BigQuery never sorts tens of millions of matches to keep a hundred; `total_rows` therefore equals `returned_rows` and `truncated` is always false. The list is for narrowing down, not counting, and the text summary says when the limit was reached. `--all` drops the `LIMIT`. Text mode leaves out `body_sha_256` and `first_seen`; `--json` is the `query` payload shape plus `table` (the fully qualified snapshot table) and `query: {protocol, title, server, status, favicon, body_hash, snapshot_hash, lookback_days}`, each filter echoed as the value bound to BigQuery (a substring as its LIKE pattern, a hash lower-cased) and unset ones omitted. `service` is the home for further protocols; a lookup of the hosts serving a configuration is coming.

#### Keeping agents under the cost cap

When an AI agent hits exit 7 (`cost_limit_exceeded`), the error hint names the `--max-cost` value that would let the query through, and the agent will often just re-run with it. To keep raising the cap a human decision, block it with a Claude Code `PreToolUse` hook. Save this as `~/.claude/hooks/block-ti-max-cost.sh` and `chmod +x` it (requires `jq`):

```sh
#!/bin/sh
# PreToolUse hook: refuse any shell command that tries to change the
# target-intel cost cap, and tell Claude to ask the user instead.
cmd=$(jq -r '.tool_input.command // empty')
if printf '%s' "$cmd" | grep -Eq -- '--max-cost|VC_TI_MAX_COST|VC_TI_PRICE_PER_TIB'; then
  echo "Blocked: changing the target-intel cost cap (--max-cost, VC_TI_MAX_COST, VC_TI_PRICE_PER_TIB) is not allowed. Stop and ask the user to run the command themselves." >&2
  exit 2
fi
exit 0
```

Then register it in `~/.claude/settings.json` (or a project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/block-ti-max-cost.sh" }
        ]
      }
    ]
  }
}
```

Exit code 2 cancels the tool call and passes the message on stderr back to Claude, so the agent stops and asks you instead of retrying. The hook also blocks `VC_TI_MAX_COST`, which sets the cap without the flag, and `VC_TI_PRICE_PER_TIB`, because the cap is converted to bytes at that price and lowering it raises the cap. Run `/hooks` in Claude Code to confirm the hook is loaded. This is a guardrail, not a security boundary: an agent can still get around it, for example by writing the flag into a script file and running that. For a hard limit, set a BigQuery custom query quota (bytes per user per day) on the billing project.


### version

```
vulncheck version [--json]
```

`--json` returns `{schema_version, version, build_date, changelog_url}` — the canonical probe for agents.


### upgrade

```
vulncheck upgrade status
vulncheck upgrade latest [--force]
vulncheck upgrade --version X.X.X
```

- `upgrade status` — check whether a newer release is available.
- `upgrade latest` — install the newest release. `--force` reinstalls the current version.
- `upgrade --version X.X.X` — install a specific version.


> [!TIP]
> Looking to plug this into your Github Repository? Check out our own [Action](https://github.com/vulncheck-oss/action)
