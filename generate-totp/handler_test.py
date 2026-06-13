import json
import pathlib
import sys

import pyotp

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import generate_totp, handle


def test_generate_totp():
    # Verification des donnees necessaires a l'activation de la 2FA.
    data = generate_totp("test@cofrap.fr")

    assert len(data["secret"]) == 32
    assert data["provisioning_uri"].startswith("otpauth://totp/")
    assert data["digits"] == 6
    assert data["period"] == 30

    # Le secret doit permettre de produire un code TOTP a six chiffres.
    current_code = pyotp.TOTP(data["secret"]).now()
    assert len(current_code) == 6
    assert current_code.isdigit()


def test_handle():
    response = handle({}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 200
    assert "secret" in body
    assert "provisioning_uri" in body
