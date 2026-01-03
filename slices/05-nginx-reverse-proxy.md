# Reverse Proxy & Header-Based Trust (nginx)

This slice adds an nginx reverse proxy in front of the Flask app and shows how **header-based identity** only makes sense if the backend enforces the proxy as a real trust boundary.

The key point:

- Through nginx, the client **cannot** spoof `X-User-ID` (nginx overwrites it).
- If the backend is reachable directly, a client **can** spoof `X-User-ID` unless the backend enforces a proxy-only signal.

## Architecture

```text
Client (curl / Postman)
  ↓
EC2 public IP (port 80)
  ↓
nginx (reverse proxy)
  ↓  (adds X-User-ID and X-From-Proxy)
app:5000 (Flask)
```
nginx config:
```
upstream app_upstream {
    server app:5000;
}

server {
    listen 80;

    location / {
        proxy_pass http://app_upstream;

        proxy_set_header X-User-ID    "1";                              # identity set by proxy
        proxy_set_header X-From-Proxy "sparringpartner-proxy-secret";   # proxy-only marker
    }
}
```
*Important*: `proxy_set_header X-User_ID "1";` means nginx overwrites any X-User_ID sent by the client. The backend never sees the client's original value when traffic goes through nginx.

**Endpoints**

- Two endpoints are added for this slice:
	- `GET /users_proxy/<id>`        # vulnerable: trusts X-User-ID as identity
	- `GET /users_proxy_safe/<id>`   # "safe": only trusts X-User-ID if proxy marker is present

**Vulnerable pattern - header as identity, no boundary enforcement**

	`users_proxy/<id>`:
			- Reads `X-User-ID` and treats it as the caller's identity
			- Returns user ID if `X-User-ID == id`
			- Does not enforce that the header came fvrom nginx

	Through nginx (port 80)	
	``
	curl http://localhost/users_proxy/1
	# nginx sends X-User-ID: 1 and X-From-Proxy: sparringpartner-proxy-secret
	# backend returns atlas (id 1)
``
Spoofing from the client via nginx does not work:
	```
	# X-User-ID: 3 from the client is overwritten by nginx back to 1
	GET http://<EC2_PUBLIC_IP>/users_proxy/3
```
Backend still sees `X-User-ID` as 1, so /users_proxy/3 returns 403.

**X-User_ID cannot be spoofed through the proxy - nginx owns that header**

The vulnerability appears when the backend is reachable directly

On the EC2 instance (bypass nginx)
```
	curl -H "X-User-ID: 1" http://localhost:5000/users_proxy/1
	# direct to Flask; backend trusts whatever X-User-ID the client sends
	```
This models:
	- We trust X-User_ID because the proxy sets it - but the backend is also reachable without the proxy

Fixed pattern — require a proxy-only signal

`/users_proxy_safe/<id>`:

Still uses `X-User-ID` as identity.

Only trusts it if a proxy-only marker is present and correct:
```
proxy_marker = request.headers.get("X-From-Proxy")
if proxy_marker != PROXY_SHARED_SECRET:
    return jsonify({"error": "forbidden"}), 403
```
Through nginx (port 80):
```
curl http://localhost/users_proxy_safe/1
# nginx adds:
#   X-User-ID: 1
#   X-From-Proxy: sparringpartner-proxy-secret
# backend returns atlas
```
Directly to Flask on 5000 (no proxy secret)
```
curl -H "X-User-ID: 1" http://localhost:5000/users_proxy_safe/1
# no X-From-Proxy -> 403 {"error":"forbidden"}
```
Rule encoded:
	- ***Headers are only identity if there is evidence they came from the trusted proxy***
	
In a real system this would be combined with:
	- backend not publicly reachable, or
	- IP / network allowlist, or
	- mTLS between proxy and app

This slice isolates the core idea:
	- Reverse proxy = trust boundary.
	- Headers are not identity unless that boundary is enforced.
***Commands Summary***
App container on 5000:
```
sudo docker run -d --name app --network sp_net -p 5000:5000 sparringpartner:aws
```
nginx fronting the app on 80:
```
sudo docker run -d \
  --name sparringpartner_nginx \
  --network sp_net \
  -p 80:80 \
  -v $HOME/sparringpartner/nginx.conf:/etc/nginx/nginx.conf:ro \
  nginx:alpine
```
***EC2 tests (proxy vs direct)***
Through nginx (port 80)
```
curl http://localhost/health
curl http://localhost/users_proxy/1
curl http://localhost/users_proxy_safe/1
```
Direct to Flask (port 5000)
```
curl http://localhost:5000/health
curl -H "X-User-ID: 1" http://localhost:5000/users_proxy/1        # succeeds (vulnerable)
curl -H "X-User-ID: 1" http://localhost:5000/users_proxy_safe/1   # 403 (safe, no proxy marker)
```
From machine (internet path)
```
http://<EC2_PUBLIC_IP>/health
http://<EC2_PUBLIC_IP>/users_proxy/1
http://<EC2_PUBLIC_IP>/users_proxy_safe/1

#IP changes when started in EC2
```
All external trafiic hits nginx on port 80
Header spoofing and bypass tests happen ***inside the instance on port 5000***
