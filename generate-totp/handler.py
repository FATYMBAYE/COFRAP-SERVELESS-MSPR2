import json

import pyotp


ISSUER_NAME = "COFRAP"
DEFAULT_ACCOUNT = "utilisateur"


def generate_totp(account_name=DEFAULT_ACCOUNT):
    """Genere un secret TOTP et les informations necessaires a la 2FA."""
    # random_base32 produit un secret aleatoire au format Base32,
    # compatible avec les applications d'authentification courantes.
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    # Cette URI sera transformee en QR code dans la prochaine fonction.
    provisioning_uri = totp.provisioning_uri(
        name=account_name,
        issuer_name=ISSUER_NAME,
    )

    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    }


def handle(event, context):
    # Point d'entree HTTP appele par OpenFaaS.
    # Pour cette premiere version, le compte utilise une valeur par defaut.
    totp_data = generate_totp()

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(totp_data)
    }
