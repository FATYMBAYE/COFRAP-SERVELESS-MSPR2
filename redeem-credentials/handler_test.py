import hashlib
import json
import pathlib
import sys
from unittest.mock import patch

from cryptography.fernet import Fernet

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import decrypt_value, handle, hash_delivery_token


def test_hash_delivery_token_uses_sha256():
    token = "jeton-test"

    assert hash_delivery_token(token) == hashlib.sha256(token.encode()).hexdigest()
    assert hash_delivery_token(token) != token


@patch("handler.read_secret")
def test_decrypt_value(mock_read_secret):
    key = Fernet.generate_key()
    encrypted = Fernet(key).encrypt(b"MotDePasse!123")
    mock_read_secret.return_value = key.decode("ascii")

    assert decrypt_value(encrypted.decode("ascii")) == "MotDePasse!123"


def test_handle_requires_token():
    response = handle({}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 400
    assert "token" in body["error"]


@patch("handler.redeem_credentials", return_value=(410, {"error": "Deja utilise."}))
def test_handle_forwards_business_status(mock_redeem):
    response = handle({"token": "abc"}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 410
    assert body["error"] == "Deja utilise."
