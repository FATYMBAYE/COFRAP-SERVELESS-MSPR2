import json
import os
from datetime import datetime, timezone

import bcrypt
import psycopg
import requests
from cryptography.fernet import Fernet
from dateutil.relativedelta import relativedelta


OPENFAAS_GATEWAY = os.getenv(
    "OPENFAAS_GATEWAY",
    "http://gateway.openfaas:8080",
)
REQUEST_TIMEOUT_SECONDS = 10


def parse_request_body(event):
    """Extrait le JSON envoye a la fonction par OpenFaaS."""
    raw_body = event.body if hasattr(event, "body") else event

    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8")

    if isinstance(raw_body, str):
        return json.loads(raw_body or "{}")

    return raw_body or {}


def call_openfaas_function(function_name):
    """Appelle une fonction interne via le gateway OpenFaaS."""
    response = requests.post(
        f"{OPENFAAS_GATEWAY}/function/{function_name}",
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def hash_password(password):
    """Hache le nouveau mot de passe avec bcrypt."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def read_secret(secret_name):
    """Lit un secret monte par OpenFaaS dans le conteneur."""
    secret_path = f"/var/openfaas/secrets/{secret_name}"
    with open(secret_path, "r", encoding="utf-8") as secret_file:
        return secret_file.read().strip()


def get_database_connection():
    """Ouvre une connexion PostgreSQL sans mot de passe dans le code."""
    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "postgres.cofrap-data.svc.cluster.local"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "cofrap"),
        user=os.getenv("POSTGRES_USER", "cofrap_app"),
        password=read_secret("cofrap-postgres-password"),
    )


def encrypt_mfa_secret(mfa_secret):
    """Chiffre le secret TOTP avant son stockage dans PostgreSQL."""
    encryption_key = read_secret("credential-delivery-key").encode("ascii")
    return Fernet(encryption_key).encrypt(mfa_secret.encode("utf-8")).decode("ascii")


def update_credentials(
    username,
    password_hash,
    mfa_secret,
    generated_at,
    expires_at,
):
    """Remplace les identifiants et desactive le compte jusqu'a la nouvelle 2FA."""
    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s,
                    mfa_secret = %s,
                    generated_at = %s,
                    expires_at = %s,
                    active = FALSE
                WHERE username = %s
                RETURNING id
                """,
                (
                    password_hash,
                    mfa_secret,
                    generated_at,
                    expires_at,
                    username,
                ),
            )
            row = cursor.fetchone()
        connection.commit()

    return None if row is None else row[0]


def rotate_credentials(username):
    """Orchestre le renouvellement du mot de passe et du secret TOTP."""
    password_data = call_openfaas_function("generate-password")
    totp_data = call_openfaas_function("generate-totp")

    new_password = password_data["password"]
    new_password_hash = hash_password(new_password)
    generated_at = datetime.now(timezone.utc)
    expires_at = generated_at + relativedelta(months=6)

    user_id = update_credentials(
        username=username,
        password_hash=new_password_hash,
        mfa_secret=encrypt_mfa_secret(totp_data["secret"]),
        generated_at=generated_at,
        expires_at=expires_at,
    )

    if user_id is None:
        return None

    # Le nouveau mot de passe est retourne une seule fois au client.
    return {
        "id": user_id,
        "username": username,
        "password": new_password,
        "provisioning_uri": totp_data["provisioning_uri"],
        "generated_at": generated_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "active": False,
    }


def json_response(status_code, body):
    """Construit une reponse HTTP JSON comprise par OpenFaaS."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handle(event, context):
    """Point d'entree HTTP de la fonction rotate-credentials."""
    try:
        request_data = parse_request_body(event)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return json_response(400, {"error": "Le corps doit etre un JSON valide."})

    username = str(request_data.get("username", "")).strip()
    if not username:
        return json_response(400, {"error": "Le champ username est obligatoire."})

    try:
        result = rotate_credentials(username)
        if result is None:
            return json_response(404, {"error": "Utilisateur introuvable."})
        return json_response(200, result)
    except requests.RequestException:
        return json_response(502, {"error": "Une fonction OpenFaaS dependante est indisponible."})
    except (KeyError, psycopg.Error):
        return json_response(500, {"error": "La rotation des identifiants a echoue."})
