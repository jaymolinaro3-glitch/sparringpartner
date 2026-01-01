from flask import Flask, jsonify, request
import jwt
import os

app = Flask(__name__)

# ---------- Fake internal "accounts" data ----------
# Treat this as data that is supposed to be internal-only,
# only reachable by the main API, not external clients.
accounts = {
    1: {"user_id": 1, "account_number": "ACC-001", "balance": 1250.50},
    2: {"user_id": 2, "account_number": "ACC-002", "balance": 990.00},
    3: {"user_id": 3, "account_number": "ACC-003", "balance": 50000.00},  # admin-ish
}

# Shared secret used for signing internal service-to-service tokens.
INTERNAL_S2S_JWT_SECRET = "sparringpartner-internal-hmac"
INTERNAL_S2S_JWT_ALGO = "HS256"

# Token helper
def decode_internal_token_from_header():
    """
    Read and verify the internal S2S token.

    Expects:
        Authorization: Internal <jwt>

    The token is a symmetric JWT signed with INTERNAL_S2S_JWT_SECRET.
    It must carry at least:
        - user_id (int)
        - role (str)
    """

    auth_header = request.headers.get("Authorization", "")
    prefix = "Internal "

    if not auth_header.startswith(prefix):
        return None, {"error": "missing or invalid Authorization header", "status": 401}

    token = auth_header[len(prefix) :].strip()
    if not token:
        return None, {"error": "missing internal token", "status": 401}

    try:
        claims = jwt.decode(
            token,
            INTERNAL_S2S_JWT_SECRET,
            algorithms=[INTERNAL_S2S_JWT_ALGO],
            options={
		"verify_exp": False,	# no exp in this demo
		"verify_aud": False,	# don't enforce audience for internal token
	    },  
        )
    except jwt.InvalidTokenError as e:
        return None, {"error": f"invalid internal token: {str(e)}", "status": 401}

    return claims, None



@app.route("/health_internal")
def health_internal():
    return jsonify({"status": "ok", "service": "internal"}), 200


# ---------- VULNERABLE internal endpoint ----------
@app.route("/internal/accounts/<int:user_id>", methods=["GET"])
def get_internal_account(user_id: int):
    """
    VULNERABLE:
    - Pretends to be "internal-only" because it expects a static header.
    - If X-Internal-Secret matches, it returns sensitive account info.
    - Any client that can reach this endpoint and set the header gets access.
    """

    # "Internal" trust signal (bad pattern)
    internal_secret = request.headers.get("X-Internal-Secret")

    if internal_secret != "hunter2":
        # Assumes that if this header isn't present, the caller isn't internal.
        return jsonify({"error": "forbidden"}), 403

    account = accounts.get(user_id)
    if not account:
        return jsonify({"error": "not found"}), 404

    return jsonify(account), 200

# ---------- SAFE internal endpoint (verified S2S token) ----------
@app.route("/internal/accounts_safe/<int:user_id>", methods=["GET"])
def get_internal_account_safe(user_id: int):
    """
    SAFE:

    - Expects a signed internal token, not a static header.
    - Token is validated server-side (signature).
    - Authorization is derived from claims inside the token.

    We enforce:
        - token.user_id must match the requested user_id.
        - (role is present and could be used for more advanced checks).
    """

    claims, err = decode_internal_token_from_header()
    if err is not None:
        status = err.get("status", 401)
        return jsonify({"error": err.get("error", "unauthorized")}), status

    token_user_id = claims.get("user_id")
    role = claims.get("role")

    # Basic authZ: only allow access to the account matching token.user_id.
    if token_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    account = accounts.get(user_id)
    if not account:
        return jsonify({"error": "not found"}), 404

    return jsonify(
        {
            "account": account,
            "token_user_id": token_user_id,
            "token_role": role,
        }
    ), 200



if __name__ == "__main__":
    # Internal service: default to loopback + debug off.
    host = os.environ.get("SP_INTERNAL_HOST", "127.0.0.1")
    debug = os.environ.get("SP_INTERNAL_DEBUG", "false").lower() == "true"

    app.run(host=host, port=6000, debug=debug)


