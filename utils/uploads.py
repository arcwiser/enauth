"""Shared limits and validation for uploaded releases."""

import os
import re

from fastapi import HTTPException, UploadFile

MAX_BUILD_BYTES = 100 * 1024 * 1024


def build_upload_limit() -> int:
    return max(1, min(int(os.getenv("MAX_BUILD_BYTES", str(MAX_BUILD_BYTES))), MAX_BUILD_BYTES))


async def read_build_upload(file: UploadFile) -> bytes:
    """Reject oversized spooled uploads before allocating their contents in RAM."""
    limit = build_upload_limit()
    if file.size is not None and file.size > limit:
        raise HTTPException(413, f"File exceeds configured limit of {limit} bytes")
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(413, f"File exceeds configured limit of {limit} bytes")
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    return content


def validate_release_name(name: str) -> str:
    """Use the same Windows-safe logical names on Windows and Linux servers."""
    clean = name.strip()
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}", clean)
            or clean.endswith((".", " "))
            or clean.split(".", 1)[0].upper() in {
                "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }):
        raise HTTPException(400, "Use a plain filename containing letters, numbers, dots, spaces, hyphens or underscores")
    return clean


def validate_release_version(version: str) -> str:
    clean = version.strip()
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+\-]{0,63}", clean):
        raise HTTPException(400, "Invalid release version")
    return clean
