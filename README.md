# CodeScan

A Snyk-style static scanner that wraps **Semgrep** (SAST) and **Trivy**
(SCA / secrets / IaC / license) behind a web UI, packaged as a single app for
the 4YI marketplace.

CodeScan runs Semgrep and Trivy as **bundled CLI tools** — it does not fork or
modify their source. No LLM, zero tokens (compute/hosting billing only).

- **Sources (v1):** public Git URL, uploaded zip/tar. (Image scan → v2.)
- **Engines:** Semgrep + Trivy, results normalized into SQLite.
- **Deploy:** single public service + persistent volume, sized for 4YI 1.5 CPU / 6 GB.

See [docs/codescan-v1-plan.md](docs/codescan-v1-plan.md) for the full v1 plan and
[docs/4yi-marketplace-deployment-guide.md](docs/4yi-marketplace-deployment-guide.md)
for the marketplace rules this repo follows.

## Develop

```sh
go run ./cmd/codescan        # serves http://localhost:8080
curl -s localhost:8080/healthz
```

Env: `HOST` (default `0.0.0.0`), `PORT` (`8080`), `DATA_DIR` (`./data`).

`CODESCAN_JOB_TIMEOUT` controls the per-job execution deadline (default `15m`).
Use a positive Go duration, for example `45m` for larger repositories; invalid
values stop startup. This changes the time budget, not the rules or scan scope.
When Security Center calls this service with a `45m` budget, configure its backend
with `CODESCAN_POLL_INTERVAL_MS=5000` and `CODESCAN_POLL_MAX_ATTEMPTS=720`.
Existing explicit polling limits take precedence over defaults. The backend
inline wait is capped at 55 minutes including queue time, so review caller
limits before increasing the engine budget further.

## Build the image

```sh
docker build -t codescan .   # bundles semgrep + trivy into the runtime image
```

## Scan scope

`POST /api/scans` accepts optional `scan_paths` for Git sources. Supply an array
of up to 20 literal directories relative to the selected branch's checkout, for
example `["apps/portal", "services/api"]`. Omitting the array or sending an
empty array scans the whole checkout. A missing directory fails the job.

Scoped jobs report the applied directories in `summary.coverage.paths` with
`version: 2`. Whole-checkout jobs retain `version: 1` and `path: "."`. Findings
use repository-relative paths. Dependency scanning uses the manifests and lock
files inside the selected directories. Use a whole-checkout scan for projects
that depend on a shared lockfile outside those directories.

Both Git requests and archive uploads support optional `path_rules`. For an
archive, supply the JSON object as a multipart field. `include` narrows the
source for code, dependency and infrastructure scanners. Supply `exclude`
lists by detector (`sast`, `sca`, `iac`). Patterns are relative to the source
root, with `*`, `?`, and `**` for nested paths. A wildcard pattern without a
slash, such as `*.test.ts`, matches at any depth. For example:

```json
{"include":["src/**"],"exclude":{"sast":["**/*.test.ts"]}}
```

Secret detection still reads the original source. Policy runs record the
effective rules and whether full-source secret detection completed under
`summary.coverage` version 3. Successful engines report available software
and ruleset versions in `summary.engine_details`.

## Milestones

- [x] **M0** skeleton: Go module, `/healthz`, SQLite migration, embedded web, Dockerfile
- [x] **M1** async core: jobs table, in-memory queue, single worker, status polling, cancel
- [x] **M2** sources: zip upload, public git clone (SSRF allowlist, zip-slip, size/timeout/cleanup guards, use-once token)
- [x] **M3** engines: Semgrep + Trivy invocation, JSON parse, normalize findings
- [x] **M4** UI: new scan / job list / results / SARIF+JSON export
- [ ] **M5** 4YI packaging & publish (vendored semgrep rules, Docker image, Import→Publish)
- [ ] **M6** real-org install + persistence acceptance
