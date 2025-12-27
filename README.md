# SparringPartner v1 — Vulnerable API (Flask)

Deliberately vulnerable Flask API built to practice product and API security reasoning, with a focus on authorization correctness. Rather than cataloging vulnerabilities, this project is structured around exploit security claims, how those claims can fail, and how to fix them correctly at the server. 

Security Claims Demonstrated
---
Claim 1  - Object access is restricted to the owning user

	A user should only be able to read or modify their own user object

Claim 2 - Privileged attributes cannot be modified by clients

	Clients must not be able to escalate privileges or modify protected fields through request input

Claim 3 - Valid token presence does not imply authorization

	A valid token must still be bound to the object the user is accessing. 

Each claim is demonstrated with:

	- A vulnerable endpoint
	- A real exploit (via Burp/Postman)
	- A fixed comparison endpoint
	- Clear evidence of break > root cause > fix. 


## Tech Stack

- Python 3.14.2
- Flask
- In-memory "users" dictionary (no real DB)
- Tested locally on Windows

To run locally:

```bash
python -m venv venv
venv\Scripts\activate
pip install flask
python app.py
```

API listens on http://127.0.0.1:5000 (or host IP when bound to 0.0.0.0).

In-Memory Users
```users = {
    1: {"id": 1, "username": "atlas",  "role": "user",  "email": "atlas@example.com"},
    2: {"id": 2, "username": "dray",   "role": "user",  "email": "dray@example.com"},
    3: {"id": 3, "username": "brenn",  "role": "admin", "email": "brenn@example.com"},
}
```
User 3 (brenn) is the admin account used in the demos.

---

API Endpoints Overview

| Method | Endpoint                     | Purpose                                                        |
|--------|-------------------------------|----------------------------------------------------------------|
| GET    | /health                      | Simple liveness probe                                          |
| GET    | /users/<id>                  | **Vulnerable** - IDOR: returns user by ID with no auth         |
| GET    | /users_secure/<id>           | **Safe** - IDOR mitigated via identity binding                 |
| PATCH  | /users/<id>                  | **Vulnerable** - Mass Assignment (can escalate privileges)     |
| PATCH  | /users_safe/<id>             | **Safe** - Mass Assignment mitigated via whitelisted fields    |
| POST   | /login						| Issues demo JWT token											 |
| GET	 | /users_token/<id>			| **Vulnerable** - BOLA with valid token (no ownership binding)  |
| GET	 | /users_token_strict/<id>     | **Safe** - Token identitiy must match object ID				 |
  
---

Vulnerability 1 — IDOR / BOLA

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

Vulnerability 2 — Mass Assignment / Privilege Escalation

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

---

Vulnerability 3 - BOLA with a Valid Token

Claim Violated
	- Valid token presence does not imply authorization

This slice demonstrates that "valid token present" does not automatically mean "authorized for this object"
	- A token provides identity, but authorization must still enforce object ownership 

Login > Token(POST /login)

Request:
```
{
  "username": "atlas"
}
```

Reponse:
```
{
  "access_token": "<JWT with sub = 1>"
}
```
The token payload is effectively:
```
{ "sub": 1 }
```
"sub" is treated as the server-side identity for user 1 (Atlas)

Vulnerable Endpoint
	- GET /users_token/<id>

Code:
```
@app.route("/users_token/<int:user_id>", methods=["GET"])
@require_token
def get_user_token(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY: ignores request.current_user_id
    return jsonify(user), 200
```

Exploit Summary

Request - Token belongs to "atlas", but path requests user 3:
```
GET /users_token/3
Authorization: Bearer <atlas_token>
```
Reponse returns brenn(admin)

**Any valid token can ready any user - BOLA even with correct authentication**

The system is still deriving authorization from client-controlled path 

---
Fixed Comparison Endpoint

Safe endpoint
	- GET /users_token_strict/<id>

Code:
```
@app.route("/users_token_strict/<int:user_id>", methods=["GET"])
@require_token
def get_user_token_strict(user_id):
    current_user_id = getattr(request, "current_user_id", None)
    if current_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(users[user_id]), 200
}
```
With the same "atlas" token (sub = 1):
	- GET /users_token_strict/3 > 403 forbidden
	- GET /users_token_strict/1 > returns atlas

**Correct behavior**
	- Authorization is enforced by comparing **token identity** (sub) to the object being access (<id>), not by trusting the URL
	

---

Tooling Used

Burp Suite Community
	- Proxy: ID tampering
	- Repeater: replaying object-level access attempt

Postman
	- Mass assignment testing
	- Token issuance and token BOLA demonstration


---


Key Takeaways

IDOR/BOLA: Do not derive authorization from client-controlled IDs (URL/path/body). Bind access control to server-side identity.

Token BOLA: A valid token does not imply authorization - identity must still be bount to the object 

Mass Assignment: Never blindly apply client JSON to server objects. Use explicit whitelists for mutable fields and protect privileged attributes.

**Authorization must always be enforced server-side, based on trusted identity and policy.** 


---

## Screenshots (Proof of Exploitation)

### IDOR (Insecure Direct Object Reference)

**1) Intercepting legitimate request**

<span>
<img src="screenshots/idor_intercept.PNG" width="750">
</span>

**2) Mutating user ID to access admin**
<span>
<img src="screenshots/idor_modified.PNG" width="750">
</span>

**3) Unauthorized admin data returned**
<span>
<img src="screenshots/idor_admin_response.PNG" width="750">
</span>

---

### Mass Assignment (Privilege Escalation)

**1) Privilege escalation via role change**
<span>
<img src="screenshots/mass_patch_admin.PNG" width="750">
</span>

**2) Verification: GET confirms admin role**
<span>
<img src="screenshots/mass_get_admin.PNG" width="750">
</span>

**3) Safe endpoint blocks role change (whitelist)**
<span>
<img src="screenshots/mass_safe_whitelist.PNG" width="750">
</span>

---

### Token BOLA

**1) Token Issuance**
<span>
<img src="screenshots/token1.PNG" width="750">
</span>

**2) Vulnerable token BOLA**
<span>
<img src="screenshots/token2.PNG" width="750">
</span>

**3) Strict endpoint blocking cross-user access**
<span>
<img src="screenshots/token3.PNG" width="750">
</span>
<span>
<img src="screenshots/token4.PNG" width="750">
</span>




