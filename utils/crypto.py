import hashlib
import hmac as hmaclib
import base64
import json
import os
import secrets
import string
import uuid
import time
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


def hash_license_key(value: str) -> str:
    """Return a deterministic, server-peppered lookup hash for a license."""
    pepper = os.getenv("LICENSE_KEY_PEPPER", "")
    if not pepper:
        raise RuntimeError("LICENSE_KEY_PEPPER is required")
    return hmaclib.new(
        pepper.encode("utf-8"),
        normalize_license_key(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def mask_license_key(value: str) -> str:
    normalized = normalize_license_key(value)
    if len(normalized) <= 12:
        return normalized[:4] + "…"
    return f"{normalized[:8]}…{normalized[-4:]}"


def _license_encryption_key() -> bytes:
    """Derive a separate AES-256 key from the required server pepper."""
    pepper = os.getenv("LICENSE_KEY_PEPPER", "")
    if not pepper:
        raise RuntimeError("LICENSE_KEY_PEPPER is required")
    return hashlib.sha256(b"enauth-license-storage-v1\0" + pepper.encode("utf-8")).digest()


def encrypt_license_key(value: str) -> str:
    """Encrypt a license for authorized later display; never store it as plaintext."""
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(_license_encryption_key()).encrypt(
        nonce, normalize_license_key(value).encode("utf-8"), b"enauth-license-key-v1"
    )
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_license_key(value: str) -> str:
    raw = base64.urlsafe_b64decode(value.encode("ascii"))
    if len(raw) < _NONCE_LEN + 17:
        raise ValueError("Invalid stored license ciphertext")
    plaintext = AESGCM(_license_encryption_key()).decrypt(
        raw[:_NONCE_LEN], raw[_NONCE_LEN:], b"enauth-license-key-v1"
    )
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
