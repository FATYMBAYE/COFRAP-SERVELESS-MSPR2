import json
import pathlib
import sys
import string


sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import SPECIAL_CHARS, handle


def test_handle():
    # On simule un appel OpenFaaS au handler.
    response = handle({}, None)
    body = json.loads(response["body"])
    password = body["password"]

    # Verification de la reponse HTTP.
    assert response["statusCode"] == 200
    assert body["length"] == 24

    # Verification de la politique de mot de passe COFRAP.
    assert len(password) == 24
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char in SPECIAL_CHARS for char in password)
