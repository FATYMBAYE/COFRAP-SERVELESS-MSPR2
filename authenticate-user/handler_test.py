import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import bcrypt
import pyotp
from cryptography.fernet import Fernet

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import authenticate, decrypt_mfa_secret, encrypt_mfa_secret, handle


PASSWORD = "MotDePasse!1234567890"
MFA_SECRET = pyotp.random_base32()
NOW = datetime(2026, 6, 7, 10, 0, tzinfo=timezone.utc)


def make_user(active=False, expired=False):
    expires_at = NOW - timedelta(days=1) if expired else NOW + timedelta(days=30)
    return {
        "id": 42,
        "username": "test@cofrap.fr",
        "password_hash": bcrypt.hashpw(
            PASSWORD.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8"),
        "mfa_secret": MFA_SECRET,
        "expires_at": expires_at,
        "active": active,
    }


@patch("handler.activate_user")
@patch("handler.decrypt_mfa_secret", return_value=(MFA_SECRET, False))
@patch("handler.get_user_by_username")
def test_authenticate_activates_user(mock_get_user, mock_decrypt, mock_activate):
    mock_get_user.return_value = make_user(active=False)
    totp_code = pyotp.TOTP(MFA_SECRET).at(NOW)

    with patch("handler.decrypt_mfa_secret", return_value=(MFA_SECRET, False)), patch(
        "handler.verify_totp", return_value=True
    ):
        status, body = authenticate(
            "test@cofrap.fr", PASSWORD, totp_code, now=NOW
        )

    assert status == 200
    assert body["authenticated"] is True
    assert body["active"] is True
    mock_activate.assert_called_once_with(42)


@patch("handler.get_user_by_username", return_value=None)
def test_authenticate_rejects_unknown_user(mock_get_user):
    status, body = authenticate("inconnu", PASSWORD, "123456", now=NOW)

    assert status == 401
    assert body["error"] == "Identifiants invalides."


@patch("handler.get_user_by_username")
def test_authenticate_rejects_wrong_password(mock_get_user):
    mock_get_user.return_value = make_user()

    status, body = authenticate("test@cofrap.fr", "mauvais", "123456", now=NOW)

    assert status == 401
    assert body["error"] == "Identifiants invalides."


@patch("handler.get_user_by_username")
def test_authenticate_rejects_wrong_totp(mock_get_user):
    mock_get_user.return_value = make_user()

    with patch("handler.decrypt_mfa_secret", return_value=(MFA_SECRET, False)), patch(
        "handler.verify_totp", return_value=False
    ):
        status, body = authenticate(
            "test@cofrap.fr", PASSWORD, "000000", now=NOW
        )

    assert status == 401
    assert body["error"] == "Code TOTP invalide."


@patch("handler.get_user_by_username")
def test_authenticate_rejects_expired_credentials(mock_get_user):
    mock_get_user.return_value = make_user(expired=True)

    with patch("handler.decrypt_mfa_secret", return_value=(MFA_SECRET, False)), patch(
        "handler.verify_totp", return_value=True
    ):
        status, body = authenticate(
            "test@cofrap.fr", PASSWORD, "123456", now=NOW
        )

    assert status == 403
    assert "expire" in body["error"]


def test_handle_requires_all_fields():
    response = handle({"username": "test@cofrap.fr"}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 400
    assert "totp_code" in body["error"]


@patch("handler.read_secret")
def test_mfa_secret_is_encrypted_and_decrypted(mock_read_secret):
    key = Fernet.generate_key()
    mock_read_secret.return_value = key.decode("ascii")

    encrypted = encrypt_mfa_secret(MFA_SECRET)
    decrypted, is_legacy = decrypt_mfa_secret(encrypted)

    assert encrypted != MFA_SECRET
    assert decrypted == MFA_SECRET
    assert is_legacy is False


@patch("handler.read_secret")
def test_plain_mfa_secret_is_detected_as_legacy(mock_read_secret):
    mock_read_secret.return_value = Fernet.generate_key().decode("ascii")

    decrypted, is_legacy = decrypt_mfa_secret(MFA_SECRET)

    assert decrypted == MFA_SECRET
    assert is_legacy is True


@patch("handler.migrate_legacy_mfa_secret")
@patch("handler.activate_user")
@patch("handler.get_user_by_username")
def test_authenticate_migrates_legacy_secret(
    mock_get_user,
    mock_activate,
    mock_migrate,
):
    mock_get_user.return_value = make_user(active=True)

    with patch(
        "handler.decrypt_mfa_secret", return_value=(MFA_SECRET, True)
    ), patch("handler.verify_totp", return_value=True):
        status, _ = authenticate(
            "test@cofrap.fr", PASSWORD, "123456", now=NOW
        )

    assert status == 200
    mock_migrate.assert_called_once_with(42, MFA_SECRET)