"""Canonical management API scopes and strict normalization helpers."""

LEGACY_API_SCOPES = ("read", "write", "admin", "*")

MANAGEMENT_API_SCOPES = (
    "apps.read",
    "apps.create",
    "apps.modify",
    "apps.secrets",
    "apps.delete",
    "products.read",
    "products.modify",
    "products.delete",
    "licenses.read",
    "licenses.generate",
    "licenses.modify",
    "licenses.reveal",
    "licenses.delete",
    "logs.read",
    "sessions.read",
    "sessions.modify",
    "builds.read",
    "builds.upload",
    "builds.delete",
    "news.read",
    "news.modify",
    "news.delete",
    "variables.read",
    "variables.modify",
    "variables.secrets",
    "variables.delete",
    "hwids.read",
    "hwids.modify",
    "resellers.read",
    "resellers.credit",
)

API_SCOPE_RESOURCES = frozenset(scope.split(".", 1)[0] for scope in MANAGEMENT_API_SCOPES)
VALID_API_SCOPES = frozenset((*LEGACY_API_SCOPES, *MANAGEMENT_API_SCOPES))


def normalize_api_scopes(value: str) -> str:
    """Validate and canonicalize a comma-separated API scope string."""
    tokens = {token.strip().lower() for token in value.split(",") if token.strip()}
    if not tokens:
        raise ValueError("At least one API scope is required")
    unknown = sorted(
        token for token in tokens
        if token not in VALID_API_SCOPES
        and not (token.endswith(".*") and token[:-2] in API_SCOPE_RESOURCES)
    )
    if unknown:
        raise ValueError(f"Unknown API scope: {unknown[0]}")
    if "*" in tokens:
        return "*"
    if "admin" in tokens:
        return "admin"
    return ",".join(sorted(tokens))
