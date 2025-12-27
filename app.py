from flask import Flask, jsonify, request
import jwt
from functools import wraps

app = Flask(__name__)

# ---------- In-memory "users" data (fake DB) ----------
users = {
    1: {"id": 1, "username": "atlas",  "role": "user",  "email": "atlas@example.com"},
    2: {"id": 2, "username": "dray",   "role": "user",  "email": "dray@example.com"},
    3: {"id": 3, "username": "brenn",  "role": "admin", "email": "brenn@example.com"},
}

# ---------- Token config (for learning only) ----------
JWT_SECRET = "sparringpartner-token-secret"
JWT_ALGO = "HS256"


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
