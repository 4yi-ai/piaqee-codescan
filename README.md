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

## Milestones

- [x] **M0** skeleton: Go module, `/healthz`, SQLite migration, embedded web, Dockerfile
- [x] **M1** async core: jobs table, in-memory queue, single worker, status polling, cancel
- [x] **M2** sources: zip upload, public git clone (SSRF allowlist, zip-slip, size/timeout/cleanup guards, use-once token)
- [x] **M3** engines: Semgrep + Trivy invocation, JSON parse, normalize findings
- [x] **M4** UI: new scan / job list / results / SARIF+JSON export
- [ ] **M5** 4YI packaging & publish (vendored semgrep rules, Docker image, Import→Publish)
- [ ] **M6** real-org install + persistence acceptance
