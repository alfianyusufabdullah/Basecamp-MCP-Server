"""
Unit tests for token encryption and Redis token storage fallback.
"""

import os
import tempfile
import pytest
from unittest import mock
import token_storage


@pytest.fixture
def temp_token_file(monkeypatch):
    """Fixture creating a temporary token file for clean testing."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    monkeypatch.setattr(token_storage, 'TOKEN_FILE', temp_path)
    yield temp_path

    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_token_encryption_decryption():
    raw_token = "secret_access_token_12345"
    encrypted = token_storage.encrypt_val(raw_token)
    assert encrypted != raw_token
    decrypted = token_storage.decrypt_val(encrypted)
    assert decrypted == raw_token


def test_unencrypted_legacy_token_fallback():
    raw_token = "legacy_unencrypted_token"
    # Decrypting an unencrypted string should safely return the original string
    decrypted = token_storage.decrypt_val(raw_token)
    assert decrypted == raw_token


def test_redis_storage_fallback_on_file(temp_token_file, monkeypatch):
    # Ensure REDIS_URL is unconfigured so fallback to file storage is tested
    monkeypatch.delenv('REDIS_URL', raising=False)

    token_storage.store_user_token(
        user_id="user_enc_1",
        access_token="secret_token_abc",
        refresh_token="secret_refresh_xyz",
        account_id="acc_enc_1"
    )

    retrieved = token_storage.get_user_token("user_enc_1")
    assert retrieved is not None
    assert retrieved['access_token'] == "secret_token_abc"
    assert retrieved['refresh_token'] == "secret_refresh_xyz"
