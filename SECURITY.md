# Security notes

AegisNexus is a defensive, educational security project.

## Intended use
Triage and investigation support. It ships **no malware**: every sample is synthetic, and uploaded files are only read as bytes.

## Threat model and controls
| Threat | Control |
|---|---|
| Prompt injection through alert text | Alert content wrapped as untrusted data; tools are read-only; the agent can only propose actions; report score comes from deterministic code |
| Malicious upload | Size limit, bytes-only processing, no parsing or execution |
| Unsafe model files | `torch.load(weights_only=True)`; weights are produced by the build, not downloaded |
| Credential attacks | scrypt hashing, per-user and IP login throttle, audit log of failures |
| Token forgery | HS256 with a random secret stored server-side; `alg` is checked; expiry enforced |
| XSS in the dashboard | All dynamic values pass through an escaping helper; CSP header in nginx |
| Container breakout | Non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges` |
| Request floods | Token-bucket rate limit per client; login throttle; upload size cap |
| Vulnerable dependencies | Dependabot, CodeQL and a Trivy image scan in GitHub Actions |
| Over-privileged users | Roles: viewer, analyst, admin, enforced on the server |

## Known limits
* Login throttling is in-memory and per process. Use a reverse proxy or Redis for multi-instance deployments.
* SQLite suits a single node. Move to Postgres for scale.
* The landing page loads Three.js from cdnjs without a subresource-integrity hash. Vendor the file (see README) for a stricter setup.
* `/metrics` is unauthenticated by design and must not be published beyond the Docker network.
* Rate limiting is in-memory and per process; use the proxy or Redis when running several instances.
* The duplicate-alert cache reuses an analysis for up to ten minutes, so similar-case hints in a reused result can be slightly stale.
* No TLS termination is included. Put it behind a TLS-terminating proxy before exposing it.
* Models trained on synthetic data must be retrained on real data before any real decision relies on them.
* The public GitHub Pages demo is static and contains no secrets.

Never commit `.env`. To report a vulnerability, open a private security advisory on the GitHub repository.
