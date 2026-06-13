import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone
from unittest.mock import patch

import bcrypt
from cryptography.fernet import Fernet

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import create_user, encrypt_value, handle, hash_password


def test_hash_password_is_not_plain_text():
    password = "MotDePasse!123"
    password_hash = hash_password(password)

    assert password_hash != password
    assert bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


@patch("handler.read_secret")
def test_encrypt_value_uses_delivery_key(mock_read_secret):
    key = Fernet.generate_key()
    mock_read_secret.return_value = key.decode("ascii")

    encrypted = encrypt_value("secret-temporaire")

    assert encrypted != "secret-temporaire"
    assert Fernet(key).decrypt(encrypted.encode("ascii")) == b"secret-temporaire"


@patch("handler.create_credential_delivery")
@patch("handler.save_user", return_value=42)
@patch("handler.encrypt_value", side_effect=lambda value: f"encrypted:{value}")
@patch("handler.call_openfaas_function")
def test_create_user_returns_only_delivery_link(
    mock_call,
    mock_encrypt,
    mock_save,
    mock_delivery,
):
    mock_call.side_effect = [
        {"password": "MotDePasse!1234567890"},
        {
            "secret": "JBSWY3DPEHPK3PXP",
            "provisioning_uri": "otpauth://totp/COFRAP:test",
        },
    ]
    mock_delivery.return_value = (
        "jeton-temporaire",
        datetime(2026, 6, 7, 10, 10, tzinfo=timezone.utc),
    )

    user = create_user("test@cofrap.fr")

    assert user["id"] == 42
    assert user["delivery_token"] == "jeton-temporaire"
    assert user["delivery_url"] == "/credentials.html?token=jeton-temporaire"
    assert "password" not in user
    assert "provisioning_uri" not in user

    stored_hash = mock_save.call_args.kwargs["password_hash"]
    assert stored_hash != "MotDePasse!1234567890"
    assert mock_save.call_args.kwargs["mfa_secret"] == (
        "encrypted:JBSWY3DPEHPK3PXP"
    )
    mock_encrypt.assert_any_call("JBSWY3DPEHPK3PXP")
    assert mock_delivery.call_args.kwargs["password"] == "MotDePasse!1234567890"


def test_handle_rejects_missing_username():
    response = handle({}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 400
    assert "username" in body["error"]


@patch("handler.create_user")
def test_handle_returns_delivery_information(mock_create):
    mock_create.return_value = {
        "id": 42,
        "username": "test@cofrap.fr",
        "delivery_token": "jeton-temporaire",
        "delivery_url": "/credentials.html?token=jeton-temporaire",
        "delivery_expires_at": "2026-06-07T10:10:00+00:00",
        "credentials_expires_at": "2026-12-07T10:00:00+00:00",
        "active": False,
    }

    response = handle({"username": "test@cofrap.fr"}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 201
    assert body["delivery_token"] == "jeton-temporaire"
    assert "password" not in body
