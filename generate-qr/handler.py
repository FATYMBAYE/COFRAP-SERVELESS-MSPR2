import base64
import io
import json

import qrcode


def create_qr_base64(provisioning_uri):
    """Cree un QR code PNG et retourne son contenu encode en Base64."""
    # Le QR code contient l'URI otpauth produite par generate-totp.
    qr_image = qrcode.make(provisioning_uri)

    # L'image est conservee en memoire : aucun fichier temporaire n'est cree.
    image_buffer = io.BytesIO()
    qr_image.save(image_buffer, format="PNG")

    # Le Base64 peut etre transporte dans une reponse JSON et affiche par le frontend.
    return base64.b64encode(image_buffer.getvalue()).decode("ascii")


def parse_request_body(event):
    """Extrait le JSON envoye a la fonction par OpenFaaS."""
    raw_body = event.body if hasattr(event, "body") else event

    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8")

    if isinstance(raw_body, str):
        return json.loads(raw_body or "{}")

    return raw_body or {}


def handle(event, context):
    # Point d'entree HTTP appele par OpenFaaS.
    try:
        request_data = parse_request_body(event)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Le corps de la requete doit etre un JSON valide."})
        }

    provisioning_uri = request_data.get("provisioning_uri")
    if not provisioning_uri:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Le champ provisioning_uri est obligatoire."})
        }

    qr_code_base64 = create_qr_base64(provisioning_uri)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "content_type": "image/png",
            "qr_code_base64": qr_code_base64,
            "data_uri": "data:image/png;base64," + qr_code_base64
        })
    }
