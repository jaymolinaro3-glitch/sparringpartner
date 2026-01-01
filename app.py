from flask import Flask, jsonify, request
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import requests

app = Flask(__name__)

# ---------- In-memory "users" data (fake DB) ----------
users = {
    1: {"id": 1, "username": "atlas",  "role": "user",  "email": "atlas@example.com"},
    2: {"id": 2, "username": "dray",   "role": "user",  "email": "dray@example.com"},
    3: {"id": 3, "username": "brenn",  "role": "admin", "email": "brenn@example.com"},
}

# ---------- Reverse proxy / header-trust slice ----------
PROXY_SHARED_SECRET = "sparringpartner-proxy-secret"

# ---------- Internal service config (Service-to-Service slice) ----------
INTERNAL_SERVICE_BASE = "http://127.0.0.1:6000"
INTERNAL_SHARED_SECRET = "hunter2"  # intentionally weak, demo only

# Stronger shared secret for signed internal tokens
INTERNAL_S2S_JWT_SECRET = "sparringpartner-internal-hmac"
INTERNAL_S2S_JWT_ALGO = "HS256"



# ---------- Token config ----------
JWT_SECRET = "sparringpartner-token-secret"
JWT_ALGO = "HS256"

def generate_stress_token(user: dict) -> str:
    """
    Issue a short-lived JWT for token stress slice.

    Claims:
      - sub: user id (int)
      - role: user["role"]
      - aud: "sparringpartner-api"
      - exp: now + 5 minutes
      - iat: issued-at timestamp
    """
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "aud": "sparringpartner-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token_from_header(expect_audience: str | None = None, allow_expired: bool = False):
    """
    Read Authorization: Bearer <token> and decode it.

    - Verifies signature.
    - If expect_audience is provided, verifies aud.
    - If allow_expired is True, skips exp verification (for the replay-vuln demo).
    - On success:
        - attaches request.current_user_id
        - attaches request.current_token_claims
        - returns (sub, claims)
    - On failure:
        - returns (None, {"error": "...", "status": <int>})
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, {"error": "missing or invalid Authorization header", "status": 401}

    token = auth_header.split(" ", 1)[1].strip()

    decode_kwargs = {
        "key": JWT_SECRET,
        "algorithms": [JWT_ALGO],
    }

    options = {}

    # Audience handling
    if expect_audience is None:
        options["verify_aud"] = False
    else:
        decode_kwargs["audience"] = expect_audience

    # Expiration handling
    if allow_expired:
        # For replay-vulnerable endpoint: accept expired tokens.
        options["verify_exp"] = False

    if options:
        decode_kwargs["options"] = options

    try:
        claims = jwt.decode(token, **decode_kwargs)
    except jwt.ExpiredSignatureError:
        return None, {"error": "token expired", "status": 401}
    except jwt.InvalidAudienceError:
        return None, {"error": "invalid audience", "status": 403}
    except jwt.InvalidTokenError as e:
        return None, {"error": f"invalid token: {str(e)}", "status": 401}

    # sub is stored as a string in the token; convert to int
    sub_claim = claims.get("sub")

    try:
        sub = int(sub_claim)
    except (TypeError, ValueError):
        return None, {"error": "invalid sub claim", "status": 403}

    # Attach to request for downstream handlers
    request.current_user_id = sub
    request.current_token_claims = claims

    return sub, claims





def generate_token(user_id: int) -> str:
    payload = {"sub": user_id}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGO],
        options={"verify_sub": False},
    )


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = decode_token(token)
        except jwt.PyJWTError:
            return jsonify({"error": "invalid token"}), 401

        user_id = payload.get("sub")
        if user_id is None:
            return jsonify({"error": "invalid token payload"}), 401

        request.current_user_id = user_id
        return fn(*args, **kwargs)

    return wrapper


# ---------- Health check ----------
@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ---------- Minimal token "login" ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")

    if not username:
        return jsonify({"error": "username required"}), 400

    matched_user = None
    for user in users.values():
        if user["username"] == username:
            matched_user = user
            break

    if not matched_user:
        return jsonify({"error": "invalid username"}), 401

    token = generate_token(matched_user["id"])
    return jsonify({"access_token": token}), 200

@app.route("/login_token_stress", methods=["POST"])
def login_token_stress():
    """
    Issue a short-lived token for the token stress slice.
    Body:
      { "username": "<name>" }

    Uses the in-memory users dict to find the user and builds a JWT with:
      sub, role, aud, exp, iat
    """
    data = request.get_json() or {}
    username = data.get("username")

    if not username:
        return jsonify({"error": "username required"}), 400

    # Look up user by username in the in-memory users dict
    user = next((u for u in users.values() if u["username"] == username), None)
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    token = generate_stress_token(user)

    return jsonify(
        {
            "access_token": token,
            "token_type": "bearer",
            "expires_in_minutes": 5,
            "aud": "sparringpartner-api",
            "sub": user["id"],
            "role": user["role"],
        }
    ), 200



# ---------- VULNERABLE IDOR ENDPOINT (GET) ----------
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY: no authentication, no ownership check
    return jsonify(user), 200


# ---------- SECURE VERSION (Requires header) ----------
@app.route("/users_secure/<int:user_id>")
def get_user_secure(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    requester_id = request.headers.get("X-User-ID")

    try:
        requester_id = int(requester_id)
    except (TypeError, ValueError):
        return jsonify({"error": "forbidden"}), 403

    if requester_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200


# ---------- MASS ASSIGNMENT VULNERABILITY (PATCH) ----------
@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    data = request.get_json() or {}
    user.update(data)
    return jsonify(user), 200


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


# ---------- TOKEN-BASED BOLA / IDOR SLICE ----------

@app.route("/users_token/<int:user_id>", methods=["GET"])
@require_token
def get_user_token(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY: ignores request.current_user_id
    return jsonify(user), 200


@app.route("/users_token_strict/<int:user_id>", methods=["GET"])
@require_token
def get_user_token_strict(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    current_user_id = getattr(request, "current_user_id", None)
    if current_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200

#------------TOKEN STRESS TEST ENDPOINTS----------
@app.route("/users_token_replay/<int:user_id>", methods=["GET"])
def users_token_replay(user_id):
    """
    VULNERABLE:
    - Allows expired tokens (allow_expired=True).
    - Does NOT bind sub (current_user_id) to user_id in the path.
    - Any token with a valid signature can read any user, even after expiry.
    """
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    sub, result = decode_token_from_header(expect_audience=None, allow_expired=True)
    if sub is None:
        status = result.get("status", 401)
        return jsonify({"error": result.get("error", "unauthorized")}), status

    # BUG: no check that sub == user_id, and we allowed expired tokens above.
    return jsonify(user), 200


@app.route("/users_token_replay_safe/<int:user_id>", methods=["GET"])
def users_token_replay_safe(user_id):
    """
    SAFE:
    - Enforces exp (no allow_expired).
    - Enforces audience "sparringpartner-api".
    - Binds sub (current_user_id) to user_id in the path.
    """
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    sub, result = decode_token_from_header(expect_audience="sparringpartner-api")
    if sub is None:
        status = result.get("status", 401)
        return jsonify({"error": result.get("error", "unauthorized")}), status

    # Correct identity binding
    if sub != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200

@app.route("/admin_token_sensitive_insecure", methods=["GET"])
def admin_token_sensitive_insecure():
    """
    VULNERABLE:
    - Only checks that the token is structurally valid.
    - Does NOT enforce role == 'admin'.
    - Any authenticated user can access this.
    """
    sub, result = decode_token_from_header(expect_audience="sparringpartner-api")
    if sub is None:
        status = result.get("status", 401)
        return jsonify({"error": result.get("error", "unauthorized")}), status

    # BUG: no role check at all.
    return jsonify(
        {
            "admin_data": "sensitive admin-only information",
            "current_user_id": sub,
            "claims": request.current_token_claims,
        }
    ), 200

@app.route("/admin_token_sensitive", methods=["GET"])
def admin_token_sensitive():
    """
    SAFE:
    - Enforces valid token.
    - Enforces role == 'admin'.
    """
    sub, result = decode_token_from_header(expect_audience="sparringpartner-api")
    if sub is None:
        status = result.get("status", 401)
        return jsonify({"error": result.get("error", "unauthorized")}), status

    claims = request.current_token_claims
    role = claims.get("role")

    if role != "admin":
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "admin_data": "sensitive admin-only information",
            "current_user_id": sub,
            "claims": claims,
        }
    ), 200



#-----------REVERSE PROXY / HEADER-TRUST SLICE------

@app.route("/users_proxy/<int:user_id>", methods=["GET"])
def get_user_via_proxy_header(user_id):
    """
    VULNERABLE:
    Treats X-User-ID as caller identity and uses it for authorization,
    without enforcing that the header actually came from the reverse proxy.
    Any client that can reach the app can spoof X-User-ID.
    """
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    header_user_id = request.headers.get("X-User-ID")

    try:
        header_user_id = int(header_user_id)
    except (TypeError, ValueError):
        # No or bad X-User-ID header -> treat as unauthorized
        return jsonify({"error": "forbidden"}), 403

    # Authorization decision based solely on header value
    if header_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200

@app.route("/users_proxy_safe/<int:user_id>", methods=["GET"])
def get_user_via_proxy_header_safe(user_id):
    """
    "SAFE" VERSION (for this slice):
    Only trusts X-User-ID when accompanied by a valid proxy marker header.
    Direct client requests that spoof X-User-ID but do not have the proxy secret
    are rejected.
    """
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    header_user_id = request.headers.get("X-User-ID")
    proxy_marker = request.headers.get("X-From-Proxy")

    # Enforce trust boundary: only honor identity header if proxy marker is valid
    if proxy_marker != PROXY_SHARED_SECRET:
        return jsonify({"error": "forbidden"}), 403

    try:
        header_user_id = int(header_user_id)
    except (TypeError, ValueError):
        return jsonify({"error": "forbidden"}), 403

    if header_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200

# ---------- Service-to-Service slice: VULNERABLE user summary ----------
@app.route("/user_summary/<int:user_id>", methods=["GET"])
def user_summary(user_id: int):
    """
    VULNERABLE Service-to-Service pattern:

    - Main API acts as "Service A"
    - Internal service (on :6000) acts as "Service B"
    - Service A calls Service B using a static header X-Internal-Secret.

    Assumptions:
    - Only Service A knows the secret and can reach Service B.

    Problem:
    - Any attacker that can reach Service B directly and send the same header
      gets the same access as Service A.
    """

    # Reuse existing in-memory users to provide some basic context.
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    try:
        resp = requests.get(
            f"{INTERNAL_SERVICE_BASE}/internal/accounts/{user_id}",
            headers={"X-Internal-Secret": INTERNAL_SHARED_SECRET},
            timeout=2.0,
        )
    except requests.RequestException as e:
        return jsonify({"error": "internal service unreachable", "detail": str(e)}), 502

    # Pass through internal errors directly for this demo.
    if resp.status_code != 200:
        return jsonify(
            {
                "error": "internal service error",
                "status": resp.status_code,
                "body": resp.text,
            }
        ), 502

    account_data = resp.json()

    # Simple combined view coming from both services.
    summary = {
        "user_id": user_id,
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "account": account_data,
    }

    return jsonify(summary), 200

# ---------- Service-to-Service slice: SAFE user summary ----------
@app.route("/user_summary_safe/<int:user_id>", methods=["GET"])
def user_summary_safe(user_id: int):
    """
    SAFE Service-to-Service pattern:

    - Main API (Service A) calls Internal Service (Service B) using a signed
      internal token instead of a static header.
    - The token carries user_id and role.
    - Internal service verifies the signature and enforces that token.user_id
      matches the requested user_id.

    This preserves the core principle:
    Authorization is derived from verified claims, not from a bare "internal" flag.
    """

    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # Build internal S2S token payload
    internal_claims = {
        "user_id": user_id,
        "role": user["role"],
        "iss": "sparringpartner-main",
        "aud": "sparringpartner-internal",
    }

    internal_token = jwt.encode(
        internal_claims,
        INTERNAL_S2S_JWT_SECRET,
        algorithm=INTERNAL_S2S_JWT_ALGO,
    )

    try:
        resp = requests.get(
            f"{INTERNAL_SERVICE_BASE}/internal/accounts_safe/{user_id}",
            headers={"Authorization": f"Internal {internal_token}"},
            timeout=2.0,
        )
    except requests.RequestException as e:
        return jsonify({"error": "internal service unreachable", "detail": str(e)}), 502

    if resp.status_code != 200:
        return jsonify(
            {
                "error": "internal service error",
                "status": resp.status_code,
                "body": resp.text,
            }
        ), 502

    data = resp.json()

    summary = {
        "user_id": user_id,
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "account": data.get("account"),
        "token_user_id": data.get("token_user_id"),
        "token_role": data.get("token_role"),
    }

    return jsonify(summary), 200




if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
