### Slice — Service-to-Service Auth (Internal Calls)

This slice models a **main API** calling an **internal service** and contrasts:

- A vulnerable pattern that trusts a static “internal” header.
- A safer pattern where the internal call is authenticated with a **signed internal token** and authorization is derived from claims, not from network location.

---

#### Architecture (High Level)

- **Service A (Main API)** — `app.py`
  - Exposes:
    - `GET /user_summary/<id>` (vulnerable S2S path)
    - `GET /user_summary_safe/<id>` (safe S2S path)
  - Calls the internal service over HTTP.

- **Service B (Internal Service)** — `internal_service.py`
  - Listens on `127.0.0.1:6000`.
  - Exposes:
    - `GET /internal/accounts/<id>` (vulnerable: header-based trust)
    - `GET /internal/accounts_safe/<id>` (safe: signed internal token)

- **Data**
  - Same in-memory `users` dict as other slices (ids 1–3).
  - Internal service has a small in-memory `accounts` map keyed by `user_id`.

---

#### Endpoints (Service-to-Service Slice)

| Service  | Method | Endpoint                          | Notes                                                  |
|---------:|--------|------------------------------------|--------------------------------------------------------|
| Main API | GET    | `/user_summary/<id>`              | Vulnerable S2S: calls `/internal/accounts/<id>`       |
| Main API | GET    | `/user_summary_safe/<id>`         | Safe S2S: calls `/internal/accounts_safe/<id>`        |
| Internal | GET    | `/internal/accounts/<id>`         | Vulnerable: trusts `X-Internal-Secret` header         |
| Internal | GET    | `/internal/accounts_safe/<id>`    | Safe: requires signed internal token (JWT-style)      |

---

#### Vulnerable Pattern — Static “Internal” Header

**Bad assumption**

> “If a request has header `X-Internal-Secret: hunter2`, it must be from a trusted internal service.”

**Vulnerable internal endpoint**

```text
GET /internal/accounts/<id>
Header: X-Internal-Secret: hunter2
```

Behavior :
	- Checks that X-Internal-Secret == "hunter2".
	- If present and correct, returns the account JSON for <id>.
	- No cryptographic verification.
	- No real notion of “which service” is calling.

**Anyone who can reach 127.0.0.1:6000 and knows/guesses hunter2 can call /internal/accounts/<id> directly and get internal data.**

Safe Pattern — Signed Internal Token (HMAC)

Improved assumption

“Internal calls must carry a signed internal token. The internal service only trusts claims that it can verify cryptographically.”

Shared internal secret

Both app.py and internal_service.py share a symmetric key, e.g.:
```
INTERNAL_S2S_JWT_SECRET = "sparringpartner-internal-hmac"
INTERNAL_S2S_JWT_ALGO = "HS256"
```

Service A (main API) signs internal tokens with this key.

Service B (internal service) verifies them with the same key.

When the main API calls the safe internal endpoint, it builds a token with claims like:
```
{
  "sub": 1,
  "role": "user",
  "aud": "sparringpartner-internal"
}
```
`sub` — user id the request is acting on.
`role` — user role (user or admin).
`aud`— audience set to "sparringpartner-internal".

How the safe internal endpoint works:
```
GET /internal/accounts_safe/<id>
Header: Authorization: Internal <signed-token>
```

Internal service:
	- Extracts the token from `Authorization: Internal <token>`.
	- Verifies the signature using `INTERNAL_S2S_JWT_SECRET` and `INTERNAL_S2S_JWT_ALGO`.
	- Verifies claims (e.g., `sub` present and integer, audience acceptable, etc.).
	- Uses `sub` as the `user_id` to look up the account and can tie behavior to role.

If verification fails:
	- Returns 401 / 403 with an error (invalid internal token, missing header, etc.).
	- Does not trust any caller that cannot produce a valid signed token.

**Safe main API wrapper**
```
GET /user_summary_safe/<id>
```
Behavior:
	- Looks up user details for <id> from the main API’s users dict.
	- Builds a signed internal token using the shared secret with:
			- sub = id
			- role = user["role"]
			- aud = "sparringpartner-internal"

Calls:
```
GET http://127.0.0.1:6000/internal/accounts_safe/<id>
Authorization: Internal <signed-token>
```
Verifies that the internal call succeeded

***Key Takeaways (Service-to-Service Auth)***

Internal call ≠ trusted call.

	- Being “inside the network” or on localhost does not make a request safe.

Static headers are not service identity.

	- `X-Internal-Secret: hunter2` is just a password in a header; it can be copied, leaked, or brute-forced.

Signed internal tokens are better, but claims still matter.

	- Use a shared secret (or mTLS / asymmetric keys in more advanced setups) to prove the caller is a specific service.
	- Derive authorization from claims inside the token (sub, role, aud), not from IP or header presence alone.

AuthZ must still be explicit.
	- Even between services, the callee should:
	
			- Verify the token.
			- Check that the claims authorize the requested action.
			- Reject requests that fail validation, regardless of network path.

This slice reinforces the same core principle used throughout SparringPartner:

Authorization must be derived from server-side, verifiable claims, not from client-controlled input, not from proxy headers, and not from network location or “internal” assumptions.
