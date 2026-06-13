import base64
import json
import pathlib
import sys

# Le dossier OpenFaaS contient un tiret dans son nom. On ajoute donc le
# dossier courant au path Python pour importer handler.py pendant les tests.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from handler import create_qr_base64, handle


PROVISIONING_URI = (
    "otpauth://totp/COFRAP:test%40cofrap.fr?"
    "secret=JBSWY3DPEHPK3PXP&issuer=COFRAP"
)


def test_create_qr_base64_returns_png():
    qr_code = create_qr_base64(PROVISIONING_URI)
    png_bytes = base64.b64decode(qr_code)

    # Une image PNG commence toujours par cette signature binaire.
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


def test_handle_returns_qr_code():
    response = handle({"provisioning_uri": PROVISIONING_URI}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 200
    assert body["content_type"] == "image/png"
    assert body["data_uri"].startswith("data:image/png;base64,")


def test_handle_rejects_missing_uri():
    response = handle({}, None)
    body = json.loads(response["body"])

    assert response["statusCode"] == 400
    assert "provisioning_uri" in body["error"]
