import json
import secrets
import string


# Politique COFRAP : mot de passe de 24 caracteres avec les 4 familles.
PASSWORD_LENGTH = 24
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password():
    """Genere un mot de passe conforme aux exigences COFRAP."""
    # On force d'abord la presence d'au moins un caractere de chaque famille.
    required_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIAL_CHARS),
    ]

    # secrets est adapte aux usages de securite, contrairement a random.
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS
    remaining_chars = [
        secrets.choice(alphabet)
        for _ in range(PASSWORD_LENGTH - len(required_chars))
    ]

    # On melange pour eviter que les caracteres obligatoires soient toujours
    # dans le meme ordre au debut du mot de passe.
    password_chars = required_chars + remaining_chars
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def handle(event, context):
    # Point d'entree appele par OpenFaaS lors d'une requete HTTP.
    password = generate_password()

    # OpenFaaS renvoie cette reponse HTTP au frontend ou au client API.
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "password": password,
            "length": PASSWORD_LENGTH,
            "policy": {
                "uppercase": True,
                "lowercase": True,
                "digits": True,
                "special": True
            }
        })
    }
