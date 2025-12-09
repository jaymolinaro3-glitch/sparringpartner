from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------- In-memory "users" data (fake DB) ----------
users = {
    1: {"id": 1, "username": "atlas",  "role": "user",  "email": "atlas@example.com"},
    2: {"id": 2, "username": "dray",   "role": "user",  "email": "dray@example.com"},
    3: {"id": 3, "username": "brenn",  "role": "admin", "email": "brenn@example.com"},
}

# ---------- Health check ----------
@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ---------- VULNERABLE IDOR ENDPOINT (GET) ----------
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY:
    # Anyone can request any user's data by changing the ID in the URL.
    # There is NO authentication and NO ownership check.
    return jsonify(user), 200


# ---------- SECURE VERSION (Requires header) ----------
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
        # Missing or non-integer header -> treat as unauthorized
        return jsonify({"error": "forbidden"}), 403

    if requester_id != user_id:
        # Enforce authorization
        return jsonify({"error": "forbidden"}), 403

    return jsonify(user), 200


# ---------- MASS ASSIGNMENT VULNERABILITY (PATCH) ----------
@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    # VULNERABILITY:
    # Blindly apply all fields from request JSON to the user object.
    data = request.get_json() or {}
    user.update(data)  # <-- mass assignment

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



if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)




