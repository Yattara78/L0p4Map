"""Regression tests for encrypted logging (P0: passphrase must actually work)."""

import base64
import hashlib
import json

import pytest

pytest.importorskip("cryptography")

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

from core.scanners.secure_logger import (  # noqa: E402
    ARCHIVE_MAGIC,
    PBKDF2_ITERATIONS,
    SecureLogger,
)


def test_same_passphrase_reopens_logs(tmp_path):
    first = SecureLogger(log_dir=str(tmp_path / "one"), encryption_key="s3cret")
    token = first.cipher.encrypt(b"scan results")

    # a fresh process with the same passphrase must read the old token
    second = SecureLogger(log_dir=str(tmp_path / "two"), encryption_key="s3cret")
    assert second.cipher.decrypt(token) == b"scan results"


def test_different_passphrase_cannot_decrypt(tmp_path):
    first = SecureLogger(log_dir=str(tmp_path / "a"), encryption_key="alpha")
    token = first.cipher.encrypt(b"payload")

    other = SecureLogger(log_dir=str(tmp_path / "b"), encryption_key="beta")
    with pytest.raises(InvalidToken):
        other.cipher.decrypt(token)


def test_password_archive_is_bound_to_the_password(tmp_path):
    logger = SecureLogger(log_dir=str(tmp_path), encryption_key="s3cret")
    logger.log_scan("tcp", "10.0.0.1", {"ports": [80, 443]})

    out = tmp_path / "archive.bin"
    assert logger.export_encrypted(str(out), password="hunter2")

    blob = out.read_bytes()
    assert blob.startswith(ARCHIVE_MAGIC)

    salt = blob[len(ARCHIVE_MAGIC):len(ARCHIVE_MAGIC) + 16]
    token = blob[len(ARCHIVE_MAGIC) + 16:]
    key = base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", b"hunter2", salt, PBKDF2_ITERATIONS)
    )
    payload = json.loads(Fernet(key).decrypt(token))
    assert payload["logs"], "exported archive is empty"

    wrong = base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", b"wrong", salt, PBKDF2_ITERATIONS)
    )
    with pytest.raises(InvalidToken):
        Fernet(wrong).decrypt(token)
