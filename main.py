import json
import os
import re
import secrets
import time
from collections import defaultdict
from pathlib import Path

from flask import Flask, request, jsonify
import bcrypt

# Configuration & Constants
DATA_DIR = Path("data")
USERS_FILE = DATA_DIR / "users.json"
POKEDEX_DIR = DATA_DIR / "pokedex"

TOKEN_TTL_SECONDS = 15 * 60       # 15 minutes token lifetime
TOKEN_ENTROPY_BYTES = 32          # 256 bits of cryptographic entropy

MAX_BODY_BYTES = 10 * 1024        # 10 KB maximum request body

# Rate-limiting parameters
LOGIN_MAX_FAILURES = 5            # Block user after 5 consecutive failures
LOGIN_LOCKOUT_SECONDS = 300       # 5 minutes lockout
SIGNUP_WINDOW_SECONDS = 60        # 1-minute sliding window
SIGNUP_MAX_PER_WINDOW = 30         # Max signup requests per IP in window (mitigates user enumeration)

# Validation Regexes
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
POKEMON_NAME_RE = re.compile(r"^[A-Za-z\s\-'.]{2,20}$")
ATTACK_NAME_RE = re.compile(r"^.{2,30}$")

VALID_TYPES = {
    "normal", "fire", "water", "grass", "electric", "ice", "fighting",
    "poison", "ground", "flying", "psychic", "bug", "rock", "ghost",
    "dragon", "dark", "steel", "fairy",
}

# Pre-computed dummy hash to mitigate timing-based user enumeration attacks on /login
_DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"timing_attack_mitigation_secret", bcrypt.gensalt(12))

# In-Memory State
# token_store: {token_string: {"username": str, "expires_at": float}}
_token_store: dict[str, dict] = {}

# login_failures: {username: {"count": int, "locked_until": float}}
_login_failures: dict[str, dict] = defaultdict(lambda: {"count": 0, "locked_until": 0.0})

# signup_attempts: {ip: [timestamp, ...]}
_signup_attempts: dict[str, list[float]] = defaultdict(list)

# Storage Helpers
DATA_DIR.mkdir(parents=True, exist_ok=True)
POKEDEX_DIR.mkdir(parents=True, exist_ok=True)


def _load_users() -> dict:
    """Load users from the JSON file. Returns an empty dict if the file does not exist."""
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_users(users: dict) -> None:
    """Persist users safely to disk."""
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def _user_pokedex_dir(username: str) -> Path:
    """
    Return the directory path for a user's Pokédex.
    The username is guaranteed to match ^[a-z0-9_]{3,20}$ from the verified token.
    """
    user_dir = (POKEDEX_DIR / username).resolve()
    return user_dir


def _dex_file(username: str, dex: int) -> Path:
    """
    Return the path to a specific Pokédex entry.
    Ensures that the resolved path never escapes the user's Pokédex directory.
    """
    user_dir = _user_pokedex_dir(username)
    target = (user_dir / f"{dex}.json").resolve()
    if not str(target).startswith(str(user_dir)):
        raise PermissionError("Path traversal attempt detected")
    return target


# Token Helpers
def _cleanup_expired_tokens() -> None:
    """Housekeeping: remove expired tokens from memory."""
    now = time.time()
    expired = [t for t, entry in _token_store.items() if entry["expires_at"] < now]
    for t in expired:
        _token_store.pop(t, None)


def _issue_token(username: str) -> str:
    """Generate an unpredictable 256-bit token with a 15-minute expiration."""
    _cleanup_expired_tokens()
    token = secrets.token_hex(TOKEN_ENTROPY_BYTES)
    _token_store[token] = {
        "username": username,
        "expires_at": time.time() + TOKEN_TTL_SECONDS,
    }
    return token


def _verify_token(token: str):
    """
    Verify the token.
    Returns the username if valid and active, or None if missing, expired, or invalid.
    """
    entry = _token_store.get(token)
    if entry is None:
        return None
    if time.time() > entry["expires_at"]:
        _token_store.pop(token, None)
        return None
    return entry["username"]


def _extract_bearer() -> str | None:
    """Extract the Bearer token string from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    return token if token else None


# Request Body Helpers
def _parse_json_body():
    """
    Safely parse the request body ensuring it does not exceed 10 KB
    and contains valid JSON representing an object.
    Returns (body_dict, None) or (None, (error_response, status_code)).
    """
    data = request.get_data()
    if len(data) > MAX_BODY_BYTES:
        return None, (jsonify({"error": "Request body too large"}), 400)
    try:
        body = json.loads(data)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None, (jsonify({"error": "Malformed JSON"}), 400)

    if not isinstance(body, dict):
        return None, (jsonify({"error": "Body must be a JSON object"}), 400)

    return body, None


# Pokédex Validation Helpers
def _validate_pokedex_entry(body: dict, url_dex: int):
    """
    Strict validation of a Pokédex document according to Section 3.
    Raises ValueError on syntax/type violations (400) or semantic rule violations (422).
    """
    allowed_top = {"dex", "name", "types", "attacks"}
    extra_fields = set(body.keys()) - allowed_top
    if extra_fields:
        raise ValueError(f"Extra fields not allowed: {', '.join(sorted(extra_fields))}")

    for field in allowed_top:
        if field not in body:
            raise ValueError(f"Missing required field: '{field}'")

    # --- dex ---
    dex = body["dex"]
    if not isinstance(dex, int) or isinstance(dex, bool):
        raise ValueError("'dex' must be an integer")
    if not (1 <= dex <= 1025):
        raise ValueError("'dex' must be an integer between 1 and 1025")
    if dex != url_dex:
        raise ValueError("'dex' in body does not match the URL")

    # --- name ---
    name = body["name"]
    if not isinstance(name, str):
        raise ValueError("'name' must be a string")
    if not POKEMON_NAME_RE.match(name):
        raise ValueError(
            "'name' must be 2 to 20 characters (letters, spaces, hyphens, apostrophes, or periods)"
        )

    # --- types ---
    types = body["types"]
    if not isinstance(types, list):
        raise ValueError("'types' must be a list")
    if not (1 <= len(types) <= 2):
        raise ValueError("'types' must contain 1 or 2 elements")
    for t in types:
        if not isinstance(t, str) or t not in VALID_TYPES:
            raise ValueError(f"Invalid Pokémon type: {t!r}")
    # Cross-field rule 1: If 2 types, they cannot be identical
    if len(types) == 2 and types[0] == types[1]:
        raise ValueError("A Pokémon cannot have two identical types")

    # --- attacks ---
    attacks = body["attacks"]
    if not isinstance(attacks, list):
        raise ValueError("'attacks' must be a list")
    if not (1 <= len(attacks) <= 20):
        raise ValueError("'attacks' must contain between 1 and 20 elements")

    attack_names_seen = set()
    allowed_attack_fields = {"name", "type", "level"}

    for i, atk in enumerate(attacks):
        if not isinstance(atk, dict):
            raise ValueError(f"Attack #{i+1} must be an object")

        extra_atk = set(atk.keys()) - allowed_attack_fields
        if extra_atk:
            raise ValueError(f"Extra fields in attack #{i+1}: {', '.join(sorted(extra_atk))}")

        for field in allowed_attack_fields:
            if field not in atk:
                raise ValueError(f"Missing required field '{field}' in attack #{i+1}")

        atk_name = atk["name"]
        if not isinstance(atk_name, str):
            raise ValueError(f"Attack #{i+1} 'name' must be a string")
        if not (2 <= len(atk_name) <= 30):
            raise ValueError(f"Attack #{i+1} 'name' must be 2 to 30 characters")

        # Cross-field rule 2: No duplicate attack names in the list
        if atk_name in attack_names_seen:
            raise ValueError(f"Duplicate attack name: {atk_name!r}")
        attack_names_seen.add(atk_name)

        atk_type = atk["type"]
        if not isinstance(atk_type, str) or atk_type not in VALID_TYPES:
            raise ValueError(f"Attack #{i+1} has invalid type: {atk_type!r}")

        atk_level = atk["level"]
        if not isinstance(atk_level, int) or isinstance(atk_level, bool):
            raise ValueError(f"Attack #{i+1} 'level' must be an integer")
        if not (1 <= atk_level <= 100):
            raise ValueError(f"Attack #{i+1} 'level' must be an integer between 1 and 100")


# Flask Application Setup
app = Flask(__name__)
# Built-in body size enforcement triggers 413, handled below to return 400
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES


# 1. GET /version (No Authentication)
@app.route("/version", methods=["GET"])
def get_version():
    return jsonify({"service": "secure-pokeapi", "version": "1.0.0"}), 200


# 2. POST /signup (No Authentication)
@app.route("/signup", methods=["POST"])
def post_signup():
    # 1. Sign-up Rate Limiting (mitigates user enumeration via 409 responses)
    client_ip = request.remote_addr or "unknown"
    now = time.time()
    _signup_attempts[client_ip] = [
        t for t in _signup_attempts[client_ip] if now - t < SIGNUP_WINDOW_SECONDS
    ]
    if len(_signup_attempts[client_ip]) >= SIGNUP_MAX_PER_WINDOW:
        return jsonify({"error": "Too many sign-up attempts. Try again later."}), 429

    # 2. Input Validation (Must occur BEFORE existence check)
    body, err = _parse_json_body()
    if err:
        return err

    if "username" not in body or "password" not in body:
        return jsonify({"error": "Missing fields: 'username' and 'password' are required"}), 400

    username = body["username"]
    password = body["password"]

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "'username' and 'password' must be strings"}), 400

    # Username pattern check -> 422
    if not USERNAME_RE.match(username):
        return jsonify({
            "error": "Username must match ^[a-z0-9_]{3,20}$ (3 to 20 lowercase letters, digits, underscore)"
        }), 422

    # Record the validated attempt towards the rate limit
    _signup_attempts[client_ip].append(now)

    # 3. Resource Existence Check -> 409
    users = _load_users()
    if username in users:
        return jsonify({"error": "User already exists"}), 409

    # 4. Secure Password Storage (bcrypt salted hash, work factor 12)
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    users[username] = {"password_hash": pw_hash}
    _save_users(users)

    # Prepare user directory
    _user_pokedex_dir(username).mkdir(parents=True, exist_ok=True)

    # Never return tokens, passwords, or hashes
    return jsonify({"username": username}), 201


# 3. POST /login (No Authentication)
@app.route("/login", methods=["POST"])
def post_login():
    GENERIC_AUTH_ERROR = {"error": "Invalid username or password"}

    # Parse body
    body, err = _parse_json_body()
    if err:
        return err

    if "username" not in body or "password" not in body:
        return jsonify({"error": "Missing fields: 'username' and 'password' are required"}), 400

    username = body.get("username")
    password = body.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "'username' and 'password' must be strings"}), 400

    now = time.time()
    failure_record = _login_failures[username]

    # Check if user is currently locked out
    if failure_record["locked_until"] > now:
        return jsonify({"error": "Too many failed login attempts. Try again later."}), 429

    users = _load_users()
    user_record = users.get(username)

    # Constant-time bcrypt execution to prevent timing-based user enumeration
    stored_hash = (
        user_record["password_hash"].encode("utf-8")
        if user_record
        else _DUMMY_BCRYPT_HASH
    )

    try:
        credentials_match = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception:
        credentials_match = False

    if not credentials_match or user_record is None:
        failure_record["count"] += 1
        if failure_record["count"] >= LOGIN_MAX_FAILURES:
            failure_record["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
            failure_record["count"] = 0
        return jsonify(GENERIC_AUTH_ERROR), 401

    # Login succeeded: reset counters and issue a fresh access token
    failure_record["count"] = 0
    failure_record["locked_until"] = 0.0

    token = _issue_token(username)
    return jsonify({"token": token}), 200


# 4. GET /user/{user}/pokedex (Authenticated)
def _authenticate_and_authorize(path_user: str):
    """
    Enforces the mandatory order:
      1. Authentication -> 401 Unauthorized (missing, malformed, invalid, or expired token).
      2. Authorization  -> 403 Forbidden (authenticated user does not match {user} in path).
    Returns (authenticated_user, None) on success, or (None, (error_response, status_code)).
    """
    raw_token = _extract_bearer()
    if raw_token is None:
        return None, (jsonify({"error": "Missing or malformed Authorization header"}), 401)

    authenticated_user = _verify_token(raw_token)
    if authenticated_user is None:
        return None, (jsonify({"error": "Invalid or expired access token"}), 401)

    # Ownership check: user can only touch their own documents
    if authenticated_user != path_user:
        return None, (jsonify({"error": "Forbidden: you can only access your own Pokédex"}), 403)

    return authenticated_user, None


def _validate_dex_param(dex_str: str):
    """
    Validate {dex} from the URL path:
      - Must be a strict positive integer (rejects '025', 'abc', '+1', '../etc') -> 400
      - Must be within [1, 1025] -> 422
    Returns (dex_int, None) or (None, (error_response, status_code)).
    """
    if not re.fullmatch(r"[1-9][0-9]*", dex_str):
        return None, (jsonify({"error": "Invalid dex: must be a strict positive integer"}), 400)

    dex = int(dex_str)
    if not (1 <= dex <= 1025):
        return None, (jsonify({"error": "dex must be an integer between 1 and 1025"}), 422)

    return dex, None


# 4. GET /user/{user}/pokedex (Authenticated)
@app.route("/user/<path:path_user>/pokedex", methods=["GET"])
def list_pokedex(path_user):
    # Step 1 (Auth) & Step 2 (Ownership)
    username, auth_err = _authenticate_and_authorize(path_user)
    if auth_err:
        return auth_err

    user_dir = _user_pokedex_dir(username)
    entries = []
    if user_dir.exists():
        for file_path in sorted(user_dir.glob("*.json"), key=lambda p: int(p.stem) if p.stem.isdigit() else 0):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                entries.append({"dex": doc["dex"], "name": doc["name"]})
            except Exception:
                continue

    return jsonify(entries), 200


# 5. GET /user/{user}/pokedex/{dex} (Authenticated)
@app.route("/user/<path:path_user>/pokedex/<dex_str>", methods=["GET"])
def get_pokedex_entry(path_user, dex_str):
    # Step 1 (Auth) & Step 2 (Ownership)
    username, auth_err = _authenticate_and_authorize(path_user)
    if auth_err:
        return auth_err

    # Step 3: Input Validation
    dex, val_err = _validate_dex_param(dex_str)
    if val_err:
        return val_err

    # Step 4: Resource Existence
    try:
        target_file = _dex_file(username, dex)
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403

    if not target_file.exists():
        return jsonify({"error": "Entry not found"}), 404

    with open(target_file, "r", encoding="utf-8") as f:
        doc = json.load(f)

    return jsonify(doc), 200


# 6. PUT /user/{user}/pokedex/{dex} (Authenticated
@app.route("/user/<path:path_user>/pokedex/<dex_str>", methods=["PUT"])
def put_pokedex_entry(path_user, dex_str):
    # Step 1 (Auth) & Step 2 (Ownership)
    username, auth_err = _authenticate_and_authorize(path_user)
    if auth_err:
        return auth_err

    # Step 3: Input Validation
    dex, val_err = _validate_dex_param(dex_str)
    if val_err:
        return val_err

    body, body_err = _parse_json_body()
    if body_err:
        return body_err

    # Validate Pokémon Schema & Cross-Field Rules
    try:
        _validate_pokedex_entry(body, dex)
    except ValueError as e:
        msg = str(e)
        structural_indicators = (
            "must be an integer", "must be a string", "must be a list",
            "must be an object", "Missing required field", "Extra fields"
        )
        if any(ind in msg for ind in structural_indicators):
            return jsonify({"error": msg}), 400
        return jsonify({"error": msg}), 422

    # Step 4: Resource Existence & Storage
    try:
        target_file = _dex_file(username, dex)
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403

    target_file.parent.mkdir(parents=True, exist_ok=True)
    already_existed = target_file.exists()

    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2)

    return jsonify(body), 200 if already_existed else 201


# 7. DELETE /user/{user}/pokedex/{dex} (Authenticated)
@app.route("/user/<path:path_user>/pokedex/<dex_str>", methods=["DELETE"])
def delete_pokedex_entry(path_user, dex_str):
    # Step 1 (Auth) & Step 2 (Ownership)
    username, auth_err = _authenticate_and_authorize(path_user)
    if auth_err:
        return auth_err

    # Step 3: Input Validation
    dex, val_err = _validate_dex_param(dex_str)
    if val_err:
        return val_err

    # Step 4: Resource Existence
    try:
        target_file = _dex_file(username, dex)
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403

    if not target_file.exists():
        return jsonify({"error": "Entry not found"}), 404

    target_file.unlink()
    return "", 204


# Error Handlers (Prevents Server Path & Stack Trace Leakage)
@app.errorhandler(400)
def handle_400(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(413)
def handle_413(e):
    return jsonify({"error": "Request body too large"}), 400


@app.errorhandler(500)
def handle_500(e):
    return jsonify({"error": "Internal server error"}), 500


# Server Entry Point
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
