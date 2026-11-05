# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Secret storage for switch, SMTP and API credentials.

Two backends, chosen automatically:
- Windows: DPAPI, bound to the current Windows user. Stored as plain hex, the format PowerShell's
  ConvertFrom-SecureString produces, so Export-Clixml credential files can be imported as-is
  without ever decrypting them.
- Other systems (Linux, Docker): AES-256-GCM, stored as "aesgcm:<base64>". The key comes from
  the LYSS_MASTER_KEY environment variable (base64, 32 bytes) or from <data dir>/master.key,
  created on first use with owner-only permissions. Back that key up: secrets cannot be
  recovered without it.
"""

import base64
import os
import re
import sys
from pathlib import Path

AESGCM_PREFIX = "aesgcm:"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
_key_file: Path | None = None  # set by inventory.configure()


def backend() -> str:
    return "dpapi" if sys.platform == "win32" and not os.environ.get("LYSS_VAULT_AESGCM") else "aesgcm"


# ---------------- Windows DPAPI ----------------

def _dpapi(protect: bool, data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes as wt

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    func = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = Blob()
    if not func(ctypes.byref(blob_in), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


# ---------------- AES-256-GCM (portable) ----------------

def _master_key() -> bytes:
    env = os.environ.get("LYSS_MASTER_KEY")
    if env:
        key = base64.b64decode(env)
    else:
        key_file = _key_file
        if key_file is None and os.environ.get("LYSS_DATA_DIR"):
            key_file = Path(os.environ["LYSS_DATA_DIR"]) / "master.key"
        if key_file is None:
            raise RuntimeError("vault key file not configured (import lyss.inventory or set LYSS_DATA_DIR)")
        if not key_file.exists():
            key_file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.b64encode(os.urandom(32)))
        key = base64.b64decode(key_file.read_bytes().strip())
    if len(key) != 32:
        raise ValueError("vault master key must be 32 bytes (base64)")
    return key


def _aesgcm(protect: bool, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(_master_key())
    if protect:
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, data, b"lyss-vault-v1")
    return aes.decrypt(data[:12], data[12:], b"lyss-vault-v1")


# ---------------- public API ----------------

def protect(secret: str) -> str:
    if backend() == "dpapi":
        return _dpapi(True, secret.encode("utf-16-le")).hex()
    return AESGCM_PREFIX + base64.b64encode(_aesgcm(True, secret.encode("utf-8"))).decode()


def unprotect(blob: str) -> str:
    if blob.startswith(AESGCM_PREFIX):
        return _aesgcm(False, base64.b64decode(blob[len(AESGCM_PREFIX):])).decode("utf-8")
    if sys.platform != "win32":
        raise RuntimeError("this secret was protected with Windows DPAPI: re-enter it on this system")
    return _dpapi(False, bytes.fromhex(blob)).decode("utf-16-le")


def read_ps_credential(path: Path) -> tuple[str, str]:
    """(username, protected password) from a PowerShell Export-Clixml PSCredential file."""
    raw = path.read_bytes()
    # Windows PowerShell 5.1 writes Export-Clixml as UTF-16 LE with a BOM
    xml = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", errors="replace")
    user = re.search(r'<S N="UserName">([^<]*)</S>', xml)
    secret = re.search(r'<SS N="Password">([0-9a-fA-F]+)</SS>', xml)
    if not user or not secret:
        raise ValueError(f"{path.name}: not a PSCredential file")
    return user.group(1), secret.group(1).lower()
