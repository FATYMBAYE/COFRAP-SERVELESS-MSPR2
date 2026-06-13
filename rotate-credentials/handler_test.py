import json
import pathlib
import sys
from unittest.mock import patch

import bcrypt
import requests
from cryptography.fernet import Fernet

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import encrypt_mfa_secret, handle, rotate_credentials


@patch("handler.update_credentials", return_value=42)
@patch("handler.encrypt_mfa_secret", return_value="secret-totp-chiffre")
@patch("handler.call_openfaas_function")
def test_rotate_credentials_updates_user(mock_call, mock_encrypt, mock_update):
    mock_call.side_effect = [
        {"password": "NouveauMotDePasse!12345"},
        {
            "secret": "JBSWY3DPEHPK3PXP",
            "provisioning_uri": "otpauth://totp/COFRAP:test",
        },
    ]

    result = rotate_credentials("test@cofrap.fr")

    assert result["id"] == 42
    assert result["password"] == "NouveauMotDePasse!12345"
    assert result["active"] is False

    stored_hash = mock_update.call_args.kwargs["password_hash"]
    assert stored_hash != result["password"]
    assert bcrypt.checkpw(
        result["password"].encode("utf-8"),
        stored_hash.encode("utf-8"),
    )
    mock_encrypt.assert_called_once_with("JBSWY3DPEHPK3PXP")
    assert mock_update.call_args.kwargs["mfa_secret"] == "secret-totp-chiffre"


@patch("handler.update_credentials", return_value=None)
@patch("handler.encrypt_mfa_secret", return_value="secret-totp-chiffre")
@patch("handler.call_openfaas_function")
def test_rotate_credentials_returns_none_for_unknown_user(
    mock_call,
    mock_encrypt,
    mock_update,
):
    mock_call.side_effect = [
        {"password": "NouveauMotDePasse!12345"},
        {
            "secret": "JBSWY3DPEHPK3PXP",
            "provisioning_uri": "otpauth://totp/COFRAP:test",
        },
    ]

    assert rotate_credentials("inconnu@cofrap.fr") is None


def test_handle_requires_username():
    response = handle({}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 400
    assert "username" in body["error"]


@patch("handler.rotate_credentials", return_value=None)
def test_handle_returns_404_for_unknown_user(mock_rotate):
    response = handle({"username": "inconnu@cofrap.fr"}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 404
    assert body["error"] == "Utilisateur introuvable."


@patch("handler.rotate_credentials", side_effect=requests.RequestException)
def test_handle_returns_502_when_dependency_fails(mock_rotate):
    response = handle({"username": "test@cofrap.fr"}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 502
    assert "indisponible" in body["error"]


@patch("handler.read_secret")
def test_encrypt_mfa_secret_uses_kubernetes_key(mock_read_secret):
    key = Fernet.generate_key()
    mock_read_secret.return_value = key.decode("ascii")

    encrypted = encrypt_mfa_secret("JBSWY3DPEHPK3PXP")

    assert encrypted != "JBSWY3DPEHPK3PXP"
    assert Fernet(key).decrypt(encrypted.encode("ascii")) == b"JBSWY3DPEHPK3PXP"