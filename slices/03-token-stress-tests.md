## Token Stress Tests (Token as Claim Carrier)

**Core claim**

> Authorization must be derived from server-side token claims (sub, role, audience, expiration), not from the mere presence of a “valid” token.

This slice treats JWTs explicitly as **claim carriers**, and shows how things break when the backend:

- Ignores expiration (`exp`)
- Ignores audience (`aud`)
- Ignores role/privilege (`role`) in admin contexts

### Token Model (for this slice)

`POST /login_token_stress` issues a short-lived JWT with:

- `sub`: user id (stored as string in the token)
- `role`: `"user"` or `"admin"` (from the in-memory `users` dict)
- `aud`: `"sparringpartner-api"`
- `iat`: issued-at (UTC)
- `exp`: `iat + 5 minutes`

Helper:

- `decode_token_from_header(expect_audience: str | None = None, allow_expired: bool = False)`
Behavior:

- Reads `Authorization: Bearer <token>`
- Verifies signature
- If `expect_audience` is set, enforces `aud == expect_audience`
- If `allow_expired=True`, disables exp verification (for replay demo)
- On success:

  - Converts `sub` string → `int`
  - Attaches `request.current_user_id` and `request.current_token_claims`
  - Returns `(sub, claims)`

- On failure: returns `(None, {"error": "...", "status": <int>})`

---
### A) Replay / Ignored Expiration

**Vulnerable endpoint**

`GET /users_token_replay/<id>`

- Calls `decode_token_from_header(expect_audience=None, allow_expired=True)`
- Explicitly disables exp verification (`verify_exp = False`)
- Does **not** check `sub == user_id` in the path
- If the token’s signature is valid, it returns whatever user ID was requested, even if the token is expired

**Effect**

- An attacker can:

  1. Obtain a valid token once
  2. Let it expire
  3. Continue using it to read arbitrary user objects

  This is both:

  - A replay issue (expired tokens still accepted)
  - An IDOR/BOLA issue (no binding between `sub` and `<id>`)
  - 
 **Safe endpoint**

`GET /users_token_replay_safe/<id>`

- Calls `decode_token_from_header(expect_audience="sparringpartner-api")`
- Does **not** allow expired tokens (`allow_expired=False` by default)
- Enforces:

  - Valid signature
  - Non-expired token
  - `aud == "sparringpartner-api"`
  - `sub == user_id` in the path

If any of those checks fail, returns `401` or `403` instead of the user object.

**Example flow (using Postman)**

1. Login as `atlas`:
```
   POST /login_token_stress
   { "username": "atlas" }
```   
Get `access_token` with `sub=1`, `role=user`

2. Call vulnerable endpoint:
```
GET /users_token_replay/3
Authorization: Bearer <ATLAS_TOKEN>
```

200, returns user 3 (admin `brenn`) - replay + identity break

3. Call safe endpoint
 ```
GET /users_token_replay_safe/3
Authorization: Bearer <ATLAS_TOKEN>
```
403, because `sub=1`, path id = 3 - forbidden

### B) Audience / Context Misuse

The helper allows enforcing audience via:
```
sub, result = decode_token_from_header(expect_audience="sparringpartner-api")
```
Vulnerable pattern
	- The backend treats any signed token as valid
If the backed does not enforce `aud`, the token is still accepted

Safe pattern
	- Every token-protected endpoint enforces audience
```
sub, result = decode_token_from_header(expect_audience="sparringpartner-api")
```
### C) Role / Privilege Misuse (BFLA)

This pair of endpoints demonstrates a Business Logic / Authorization failure where a valid token is treated as sufficient permission, even though the action should be restricted to admins.

#### Vulnerable endpoint — missing role enforcement

`GET /admin_token_sensitive_insecure`

Behavior:

- Verifies the token is structurally valid (signature, etc.)
- **Does not check the `role` claim**
- Any authenticated token can access the endpoint

Effect:

- A normal user (`role="user"`) can invoke an admin-only action
- The system treats “has a token” as equivalent to “is authorized”

This models a classic **BFLA (Business Flow / Logic Abuse)** condition:
authorization is assumed instead of explicitly enforced.

---

#### Secure endpoint — explicit role validation

`GET /admin_token_sensitive`

Behavior:

- Calls `decode_token_from_header(expect_audience="sparringpartner-api")`
- Reads `role` from `request.current_token_claims`
- Enforces server-side privilege:

```python
if role != "admin":
    return jsonify({"error": "forbidden"}), 403
```

***Core lesson***

A valid token does not imply correct authorization.

Roles and privileges must be enforced explicitly

Authorization must come from server-side evaluation of claims

Business logic = part of the security boundary
