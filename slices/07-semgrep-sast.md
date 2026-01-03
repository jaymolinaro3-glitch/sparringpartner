### Slice — Semgrep SAST Integration (Evidence, Not Checkbox)

This slice wires **Semgrep** into SparringPartner and treats SAST as *input* to reasoning, not an oracle. The goal is:

- Run a real ruleset against the repo.
- Inspect findings in context of SparringPartner’s authZ + trust boundary design.
- Decide for each: **fix** vs **justify**.
- Capture evidence (before/after + reasoning) in the repo.

---

#### Semgrep Command

All scans were run via Docker from the repo root:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -w /src \
  returntocorp/semgrep semgrep scan --config=p/owasp-top-ten .
```
Finding 1 — Dockerfile runs as root (FIXED)
Rule: dockerfile.security.missing-user.missing-user
Location: Dockerfile (CMD ["python", "app.py"] with no USER)

Semgrep claim:

	- By not specifying a USER, a program in the container may run as 'root'.

Context in SparringPartner

	- Docker image is used in the Docker and AWS slices.

	- Running as root inside the container is not required for any of the lab behavior.

	- This is a safe, low-friction improvement that doesn’t distract from authZ logic.

Code change

Dockerfile updated from “no USER” to a non-root user:
```
FROM python:3.11-slim

# Create non-root user
RUN useradd -m appuser

WORKDIR /app

# Copy application code
COPY app.py /app/
COPY internal_service.py /app/

# Install runtime deps
RUN pip install --no-cache-dir flask PyJWT requests

# Drop privileges: run as non-root
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
```
Effect

	- Semgrep missing-user finding disappears.

	- Behavior in Docker/AWS slices is unchanged, except the process no longer runs as root inside the container.

Takeaway:

***Some SAST findings are cheap, meaningful hardening wins. When the fix is low-risk and doesn’t distort the learning goal, apply it.***

Finding 2 — Flask app.run(host="0.0.0.0", debug=True) (FIXED VIA CONFIG)

Rules:

	- python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host

	- python.flask.security.audit.debug-enabled.debug-enabled

Locations:

	- app.py: app.run(host="0.0.0.0", debug=True)

	- internal_service.py: app.run(host="0.0.0.0", port=6000, debug=True)

Semgrep claims:

	- Running flask app with host 0.0.0.0 could expose the server publicly.
	- Detected Flask app with debug=True. Do not deploy to production with this flag enabled.

Context in SparringPartner

	- In the local and Docker flows, this was mainly convenience: bind to all interfaces, debug on.

	- In the AWS slice, binding to 0.0.0.0 on EC2 + open security group can genuinely expose the lab APIs and debugger to the internet.

Rather than pretending this is “fine”, the code was updated so:

	- Defaults are safe for local execution.

	- “Dangerous” behavior is explicitly driven by environment variables when needed for lab slices.

Code change — main app
```
import os
...
if __name__ == "__main__":
    # Default: safe for local dev (loopback + debug off).
    # Docker/AWS slices can override via env vars.
    host = os.environ.get("SP_APP_HOST", "127.0.0.1")
    debug = os.environ.get("SP_APP_DEBUG", "false").lower() == "true"

    app.run(host=host, debug=debug)
```
Code change - Internal Service
```
import os
...
if __name__ == "__main__":
    # Internal service: default to loopback + debug off.
    host = os.environ.get("SP_INTERNAL_HOST", "127.0.0.1")
    debug = os.environ.get("SP_INTERNAL_DEBUG", "false").lower() == "true"

    app.run(host=host, port=6000, debug=debug)
```
Behavior

	- Default run: 127.0.0.1, debug=False → Semgrep’s Flask host/debug findings are gone.

	- Lab slices that need exposure: explicitly set env vars, e.g.:
```
SP_APP_HOST=0.0.0.0 SP_APP_DEBUG=true python app.py
```
Takeaway:

	- SAST surfaced a real production risk. The fix is not “never bind to 0.0.0.0”, it’s “make the default safe and make unsafe behavior explicit and intentional.”

Finding 3 — SSRF on internal requests.get (JUSTIFIED / DOCUMENTED)

Rule: python.flask.security.injection.ssrf-requests.ssrf-requests
Locations (simplified):
```
resp = requests.get(
    f"{INTERNAL_SERVICE_BASE}/internal/accounts/{user_id}",
    headers={"X-Internal-Secret": INTERNAL_SHARED_SECRET},
    timeout=2.0,
)

resp = requests.get(
    f"{INTERNAL_SERVICE_BASE}/internal/accounts_safe/{user_id}",
    headers={"Authorization": f"Internal {internal_token}"},
    timeout=2.0,
)
```
Semgrep claim:

	- Data from request object is passed to a new server-side request. This could lead to SSRF.

Context in SparringPartner

	- INTERNAL_SERVICE_BASE is a fixed, internal URL (e.g. http://127.0.0.1:6000).

	- The only attacker-controlled value here is the integer user_id in the path.

	- Hostname and scheme are not attacker-controlled.

	- Responses are wrapped and not streamed raw in a way that turns this into an “open proxy”.

Conclusion: in this architecture, there is no path for an attacker to pivot these calls into:

	- contacting arbitrary internal hosts, or

	- using the app as a generic SSRF proxy.

Decision

	- Finding is kept as a reminder of SSRF patterns, but documented as not exploitable in this specific design.

	- If INTERNAL_SERVICE_BASE ever became user-controlled or derived from headers, this would be revisited and treated as a real SSRF risk.

Takeaway

	- SAST flagged a generic “request from request” pattern. Architecture and constants matter: without control of scheme/host, this is not SSRF, but it’s still a useful red flag if the design changes later.

Overall SAST Slice Takeaways
SAST is not the truth; it’s an input to reasoning:

	- Some findings are cheap, high-value fixes (non-root user, safer defaults).

	- Some are real risks for production but intentionally tolerated in a lab (hardcoded secrets).

	- Some are only risks under different architectural assumptions (SSRF, Host header).

The important part is the chain:

	- Tool output → architectural context → exploitability analysis → fix or documented justification.
