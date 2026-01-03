# Dockerized Deployment & Trust Boundary Notes

This slice wraps the Flask API in a single Docker container to make the deployment context more realistic, without jumping into orchestration or Kubernetes.

## Dockerfile (simplified view)

- Base image: `python:3.11-slim`
- Copies `app.py` into `/app`
- Installs `flask` and `PyJWT`
- Exposes port `5000`
- Starts the app with `python app.py` (Flask bound to `0.0.0.0` inside the container)

Build:

```bash
docker build -t sparringpartner:dev .
```
Run:
```
docker run --rm -p 5000:5000 --name sparringpartner sparringpartner:dev
```
The API is then reachable at:
```
http://localhost:5000
```
## Trust Boundary — Before vs After Docker

### Before (bare process)

- Flask ran directly on the host (Windows), bound to `127.0.0.1` and/or a LAN IP like `10.x.x.x`.
- The trust boundary for network access was:
  - The OS network stack
  - Host firewall rules
  - Anything else on the same machine could potentially talk to the app

### After (single Docker container)

- The app runs as a process inside a container namespace
- Internally, Flask still binds to `0.0.0.0:5000` **inside the container**
- The host decides how (and whether) to expose that port via `-p` flags

The new trust boundary is:

> Anything that can reach the **published host port** can now reach the vulnerable API inside the container.

On a laptop with no inbound exposure, this is mostly local.  
On a cloud VM with a public IP and open firewall, the same command makes the lab API **internet-accessible**.

---

## Exposure Changes with `0.0.0.0` and Port Publishing

Inside the container, binding to `0.0.0.0` means:

> “Accept connections on any container interface.”

That only matters externally once a port is published:

- `-p 5000:5000` maps **host port 5000 → container port 5000**

If the host’s `0.0.0.0:5000` is reachable from the internet (cloud VM, insecure security group, etc.), then every intentionally vulnerable endpoint becomes externally reachable.

Key lesson:

> “Just a local learning API” becomes a real attack surface once the host is exposed.  
> Docker does not secure the API — it changes the **delivery context and exposure**.

---

## Realistic Failure Modes (Single-Container Level)

**1) Accidental internet exposure of a lab container**

- Developer runs this container on a cloud VM with:
  - `-p 5000:5000`
  - Public IP
  - Security group open to `0.0.0.0/0`
- The vulnerable API (IDOR, mass assignment, token BOLA) becomes public attack surface
- Assumption *“it’s just a local lab”* is false in that deployment context

**2) Misplaced trust in “container isolation”**

- Team assumes *“it’s in Docker so it’s isolated”*
- Another service on the same host (or same Docker network) can still reach:
  - `http://localhost:5000`
  - `http://sparringpartner:5000`
- Any SSRF or internal request from a more-privileged service can hit this API and exploit insecure endpoints

Practical takeaway:

> **Network reachability**, not “container vs bare metal,” determines who can attack the app.

---

This slice is intentionally limited to **single-container awareness**:

- No orchestration, Compose, or Kubernetes
- Focus = **exposure, port publishing, and trust-boundary shifts when an API is containerized**

---

# Minimal AWS Deployment & Internet-Facing Claims

In this slice, SparringPartner is deployed as a Dockerized container on a single EC2 instance in AWS. The goal is not production DevOps — the goal is to make the API **genuinely internet-reachable** and reason about the security claims that context creates.

## Path: Client → Internet → AWS → EC2 → Docker → Flask

```

Client (Browser / Postman)
  ↓
Public Internet
  ↓
AWS (routing + public IP)
  ↓
EC2 instance (security group controls who can reach port 80)
  ↓
Docker (host 80 → container 5000)
  ↓
Flask app (vulnerable endpoints)
```
- EC2 exposes a public IPv4 address
- Security group allows inbound HTTP/80 from whitelisted IP adress (MyIP)
- Docker maps '80>5000'
  ```
  docker run -d -p 80:5000 sparringpartner:aws
  ```
- Flask still listens on '0.0.0.0:5000' inside the container

  Result:
  	- The same vulnerable API is now reachable from the internet, subject to cloud-level network controls

 ## Internet-Facing Security Claims (Falsifiable)

**Claim A — Only my IP can reach the API**

- Enforcement point: EC2 Security Group inbound rule on TCP/80 = *My IP only*
- What would falsify this claim:
  - Changing the rule to `0.0.0.0/0`
  - Adding another security group or load balancer that exposes the instance indirectly
  - Observing the API is reachable from a different network or device

**Claim B — The API is only reachable via port 80**

- Enforcement point: only TCP/80 is open (SSH 22 is restricted to My IP)
- What would falsify this claim:
  - Opening additional inbound ports (e.g., 5000, 8080)
  - Starting another container or process and exposing it
  - A scan from another host shows more listening services

**Claim C — Cloud deployment does not change application-layer risk**

- The same intentional vulnerabilities remain:
  - `/users/<id>` → IDOR / BOLA
  - `PATCH /users/<id>` → Mass assignment
  - `/users_token/<id>` → Token-based BOLA
- What would falsify misunderstanding:
  - Assuming “it’s in AWS so it’s protected”
  - Treating network controls as a substitute for authorization
  - Exposing the instance to the internet and seeing the same flaws remain exploitable
 
