import hashlib
import hmac as hmaclib
import base64
import json
import os
import secrets
import string
import uuid
import time
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ─── Key Derivation ──────────────────────────────────────────────────────────
# PBKDF2-SHA256 with a per-request random salt.
# The salt is prepended to the ciphertext so the server can re-derive the key.

_PBKDF2_ITERATIONS = 100_000
_SALT_LEN          = 16   # bytes
_NONCE_LEN         = 12   # bytes — standard for AES-GCM


def derive_key(app_secret: str, salt: bytes) -> bytes:
    """PBKDF2-SHA256(app_secret, salt, 100k iters) → 32-byte AES key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(app_secret.encode("utf-8"))


# ─── AES-256-GCM Authenticated Encryption ───────────────────────────────────
# Wire format: base64( salt[16] | nonce[12] | ciphertext+tag )
# The GCM tag (16 bytes) is appended automatically by AESGCM.encrypt().

def encrypt_payload(data: dict, app_secret: str) -> str:
    """Encrypt dict with AES-256-GCM. Returns base64(salt[16] + nonce[12] + ciphertext+tag)."""
    salt  = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key   = derive_key(app_secret, salt)

    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    aesgcm    = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)   # includes 16-byte GCM tag

    return base64.b64encode(salt + nonce + ciphertext).decode("utf-8")


def encrypt_bytes(value: bytes, secret: str) -> str:
    """Encrypt arbitrary bytes with the same versioned AES-256-GCM envelope."""
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(derive_key(secret, salt)).encrypt(nonce, value, None)
    return base64.b64encode(salt + nonce + ciphertext).decode("ascii")


def decrypt_bytes(value_b64: str, secret: str) -> bytes:
    """Decrypt an arbitrary-byte AES-256-GCM envelope."""
    raw = base64.b64decode(value_b64, validate=True)
    if len(raw) < _SALT_LEN + _NONCE_LEN + 16:
        raise ValueError("Ciphertext too short")
    salt = raw[:_SALT_LEN]
    nonce = raw[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ciphertext = raw[_SALT_LEN + _NONCE_LEN:]
    try:
        return AESGCM(derive_key(secret, salt)).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed") from exc


def derive_session_download_secret(app_secret: str, token: str, hwid: str, file_id: str) -> str:
    """Derive a unique download key scoped to one session, device, and file."""
    context = f"download-v1|{token}|{hwid}|{file_id}".encode("utf-8")
    return hmaclib.new(app_secret.encode("utf-8"), context, hashlib.sha256).hexdigest()


def derive_ticket_download_secret(ticket: str, token: str, hwid: str, file_id: str) -> str:
    """Derive an authenticated payload key unique to a one-use ticket and bound session."""
    context = f"download-v2|{token}|{hwid}|{file_id}".encode("utf-8")
    return hmaclib.new(ticket.encode("utf-8"), context, hashlib.sha256).hexdigest()


def decrypt_payload(data_b64: str, app_secret: str) -> dict:
    """Decrypt base64(salt[16] + nonce[12] + ciphertext+tag) with AES-256-GCM."""
    raw = base64.b64decode(data_b64)
    min_len = _SALT_LEN + _NONCE_LEN + 16 + 1   # salt + nonce + tag + at least 1 byte
    if len(raw) < min_len:
        raise ValueError("Ciphertext too short")

    salt      = raw[:_SALT_LEN]
    nonce     = raw[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ciphertext = raw[_SALT_LEN + _NONCE_LEN:]

    key    = derive_key(app_secret, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — bad key, tampered ciphertext, or invalid tag")

    return json.loads(plaintext.decode("utf-8"))


# ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────
# Signature now covers: app_id + "|" + timestamp + "|" + data_b64
# This binds the signature to the specific app and prevents cross-app replay.

def compute_signature(app_secret: str, data_b64: str, timestamp: int,
                      app_id: str = "") -> str:
    msg = f"{app_id}|{timestamp}|{data_b64}".encode("utf-8")
    return hmaclib.new(app_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_signature(app_secret: str, data_b64: str, timestamp: int,
                     sig: str, app_id: str = "") -> bool:
    expected = compute_signature(app_secret, data_b64, timestamp, app_id)
    return hmaclib.compare_digest(expected, sig)


# ─── Generators ──────────────────────────────────────────────────────────────

def generate_license_key() -> str:
    """6 groups of 6 uppercase alphanumeric chars — 36^6 ≈ 2.18 billion combos per group."""
    chars = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(chars) for _ in range(6)) for _ in range(6)]
    return "-".join(groups)


def normalize_license_key(value: str) -> str:
    return value.strip().upper()


_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _parse_previous_keys(env_name: str) -> dict[str, str]:
    raw = os.getenv(env_name, "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be a JSON object") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    result = {}
    for key_id, secret in value.items():
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise RuntimeError(f"{env_name} contains an invalid key ID")
        if not isinstance(secret, str) or len(secret) < 32:
            raise RuntimeError(f"{env_name} keys must contain at least 32 characters")
        result[key_id] = secret
    return result


def _legacy_license_secret() -> str:
    secret = os.getenv("LICENSE_KEY_PEPPER", "")
    if not secret:
        raise RuntimeError("License key configuration is required")
    return secret


def _license_lookup_keyring() -> tuple[str, dict[str, str]]:
    current_secret = os.getenv("LICENSE_LOOKUP_KEY", "").strip()
    current_id = os.getenv("LICENSE_LOOKUP_KEY_ID", "v1").strip()
    if current_secret:
        if len(current_secret) < 32:
            raise RuntimeError("LICENSE_LOOKUP_KEY must contain at least 32 characters")
        if not _KEY_ID_RE.fullmatch(current_id):
            raise RuntimeError("LICENSE_LOOKUP_KEY_ID is invalid")
        keys = _parse_previous_keys("LICENSE_LOOKUP_PREVIOUS_KEYS")
        if current_id in keys:
            raise RuntimeError("Current lookup key ID cannot also be a previous key")
        keys[current_id] = current_secret
        return current_id, keys
    return "legacy-v1", {"legacy-v1": _legacy_license_secret()}


def _license_encryption_keyring() -> tuple[str, dict[str, str]]:
    current_secret = os.getenv("LICENSE_ENCRYPTION_KEY", "").strip()
    current_id = os.getenv("LICENSE_ENCRYPTION_KEY_ID", "v1").strip()
    if current_secret:
        if len(current_secret) < 32:
            raise RuntimeError("LICENSE_ENCRYPTION_KEY must contain at least 32 characters")
        if not _KEY_ID_RE.fullmatch(current_id):
            raise RuntimeError("LICENSE_ENCRYPTION_KEY_ID is invalid")
        keys = _parse_previous_keys("LICENSE_ENCRYPTION_PREVIOUS_KEYS")
        if current_id in keys:
            raise RuntimeError("Current encryption key ID cannot also be a previous key")
        keys[current_id] = current_secret
        legacy = os.getenv("LICENSE_KEY_PEPPER", "").strip()
        if legacy:
            keys.setdefault("legacy-v1", legacy)
        return current_id, keys
    return "legacy-v1", {"legacy-v1": _legacy_license_secret()}


def validate_license_key_configuration() -> None:
    """Fail fast on ambiguous or accidentally shared license-key secrets."""
    _, lookup_keys = _license_lookup_keyring()
    _, encryption_keys = _license_encryption_keyring()

    def reject_duplicates(label: str, keys: dict[str, str]) -> None:
        seen: dict[str, str] = {}
        for key_id, secret in keys.items():
            previous_id = seen.get(secret)
            if previous_id is not None:
                raise RuntimeError(
                    f"{label} key IDs {previous_id!r} and {key_id!r} use the same secret"
                )
            seen[secret] = key_id

    reject_duplicates("License lookup", lookup_keys)
    reject_duplicates("License encryption", encryption_keys)

    for lookup_id, lookup_secret in lookup_keys.items():
        for encryption_id, encryption_secret in encryption_keys.items():
            if lookup_secret != encryption_secret:
                continue
            if (lookup_id, encryption_id) == ("legacy-v1", "legacy-v1"):
                continue
            raise RuntimeError(
                f"License secret reuse detected between lookup {lookup_id!r} "
                f"and encryption {encryption_id!r}"
            )


def current_license_lookup_key_id() -> str:
    return _license_lookup_keyring()[0]


def license_lookup_hashes(value: str) -> list[tuple[str, str]]:
    """Return current then previous versioned hashes for zero-downtime lookup rotation."""
    current_id, keys = _license_lookup_keyring()
    normalized = normalize_license_key(value).encode("utf-8")
    ordered_ids = [current_id, *(key_id for key_id in keys if key_id != current_id)]
    return [
        (key_id, hmaclib.new(keys[key_id].encode("utf-8"), normalized, hashlib.sha256).hexdigest())
        for key_id in ordered_ids
    ]


def hash_license_key(value: str) -> str:
    """Return a deterministic, server-peppered lookup hash for a license."""
    return license_lookup_hashes(value)[0][1]


def mask_license_key(value: str) -> str:
    normalized = normalize_license_key(value)
    if len(normalized) <= 12:
        return normalized[:4] + "…"
    return f"{normalized[:8]}…{normalized[-4:]}"


def _derive_license_encryption_key(secret: str, version: bytes) -> bytes:
    return hashlib.sha256(version + b"\0" + secret.encode("utf-8")).digest()


def encrypt_license_key(value: str) -> str:
    """Encrypt a license for authorized later display; never store it as plaintext."""
    key_id, keys = _license_encryption_keyring()
    nonce = os.urandom(_NONCE_LEN)
    aad = f"enauth-license-key-v2|{key_id}".encode("ascii")
    ciphertext = AESGCM(_derive_license_encryption_key(keys[key_id], b"enauth-license-storage-v2")).encrypt(
        nonce, normalize_license_key(value).encode("utf-8"), aad
    )
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"v2.{key_id}.{encoded}"


def decrypt_license_key(value: str) -> str:
    _, keys = _license_encryption_keyring()
    if value.startswith("v2."):
        try:
            _, key_id, encoded = value.split(".", 2)
            secret = keys[key_id]
        except (ValueError, KeyError) as exc:
            raise ValueError("Unknown license encryption key version") from exc
        raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
        aad = f"enauth-license-key-v2|{key_id}".encode("ascii")
        derived = _derive_license_encryption_key(secret, b"enauth-license-storage-v2")
    else:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        aad = b"enauth-license-key-v1"
        if "legacy-v1" not in keys:
            raise ValueError("Legacy license encryption key is unavailable")
        derived = _derive_license_encryption_key(keys["legacy-v1"], b"enauth-license-storage-v1")
    if len(raw) < _NONCE_LEN + 17:
        raise ValueError("Invalid stored license ciphertext")
    plaintext = AESGCM(derived).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], aad)
    return plaintext.decode("utf-8")


def display_license_key(masked: str, ciphertext: str | None) -> str:
    """Return the authorized full key when available, otherwise its legacy mask."""
    if not ciphertext:
        return masked
    try:
        return decrypt_license_key(ciphertext)
    except Exception:
        return masked


def generate_app_secret() -> str:
    """64 hex chars = 256 bits of entropy."""
    return secrets.token_hex(64)


def generate_session_token() -> str:
    """64 URL-safe bytes = 512 bits of entropy."""
    return secrets.token_urlsafe(64)


def generate_uid() -> str:
    return str(uuid.uuid4())


# ─── Password ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    import bcrypt
    # Work factor 12 — ~300ms on modern hardware, impractical to brute-force
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


_DUMMY_PASSWORD_HASH = "$2b$12$sdzJF97gQQ/es0bk6xUQVOZNX7T/ldjKG.ISDc2b8TyeTHrI/Nai6"


def verify_password_constant_time(password: str, hashed: str | None) -> bool:
    """Always perform a bcrypt check so missing accounts do not create a timing oracle."""
    candidate = hashed or _DUMMY_PASSWORD_HASH
    try:
        valid = verify_password(password, candidate)
    except (TypeError, ValueError):
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return False
    return bool(hashed) and valid


# ─── HWID Validation ─────────────────────────────────────────────────────────

def is_valid_hwid(hwid: str) -> bool:
    """
    Expect the client to send a SHA-256 hex digest (64 chars) or
    a SHA-512 hex digest (128 chars). Reject anything else to prevent
    trivially forged/empty HWIDs.
    """
    if not hwid:
        return False
    h = hwid.lower()
    if len(h) not in (64, 128):
        return False
    return all(c in "0123456789abcdef" for c in h)
