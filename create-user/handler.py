import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import psycopg
import requests
from cryptography.fernet import Fernet
from dateutil.relativedelta import relativedelta


# Dans Kubernetes, les fonctions OpenFaaS sont joignables par le gateway interne.
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
    """Hache le mot de passe avec bcrypt avant son stockage."""
    password_bytes = password.encode("utf-8")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def read_secret(secret_name):
    """Lit un secret monte par OpenFaaS dans le conteneur."""
    secret_path = f"/var/openfaas/secrets/{secret_name}"
    with open(secret_path, "r", encoding="utf-8") as secret_file:
        return secret_file.read().strip()


def get_database_connection():
    """Ouvre une connexion PostgreSQL sans exposer le mot de passe dans le code."""
    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "postgres.cofrap-data.svc.cluster.local"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "cofrap"),
        user=os.getenv("POSTGRES_USER", "cofrap_app"),
        password=read_secret("cofrap-postgres-password"),
    )


def save_user(username, password_hash, mfa_secret, generated_at, expires_at):
    """Enregistre l'utilisateur et retourne son identifiant."""
    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    mfa_secret,
                    generated_at,
                    expires_at,
                    active
                )
                VALUES (%s, %s, %s, %s, %s, FALSE)
                RETURNING id
                """,
                (
                    username,
                    password_hash,
                    mfa_secret,
                    generated_at,
                    expires_at,
                ),
            )
            user_id = cursor.fetchone()[0]
        connection.commit()
    return user_id


def encrypt_value(value):
    """Chiffre une information temporaire avec la cle stockee dans Kubernetes."""
    encryption_key = read_secret("credential-delivery-key").encode("ascii")
    return Fernet(encryption_key).encrypt(value.encode("utf-8")).decode("ascii")


def create_credential_delivery(user_id, password, provisioning_uri, created_at):
    """Cree une remise valable dix minutes et retourne son jeton brut."""
    delivery_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(delivery_token.encode("utf-8")).hexdigest()
    delivery_expires_at = created_at + timedelta(minutes=10)

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO credential_deliveries (
                    user_id,
                    token_hash,
                    password_ciphertext,
                    provisioning_uri_ciphertext,
                    created_at,
                    expires_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    token_hash,
                    encrypt_value(password),
                    encrypt_value(provisioning_uri),
                    created_at,
                    delivery_expires_at,
                ),
            )
        connection.commit()

    return delivery_token, delivery_expires_at

def create_user(username):
    """Orchestre la creation complete d'un compte COFRAP."""
    password_data = call_openfaas_function("generate-password")
    totp_data = call_openfaas_function("generate-totp")

    # Le mot de passe en clair est retourne une seule fois au client.
    password = password_data["password"]
    password_hash = hash_password(password)

    generated_at = datetime.now(timezone.utc)
    expires_at = generated_at + relativedelta(months=6)

    user_id = save_user(
        username=username,
        password_hash=password_hash,
        # Le secret TOTP doit rester recuperable pour verifier les codes.
        # Il est donc chiffre avec Fernet, contrairement au mot de passe
        # qui est hache de maniere irreversible avec bcrypt.
        mfa_secret=encrypt_value(totp_data["secret"]),
        generated_at=generated_at,
        expires_at=expires_at,
    )

    delivery_token, delivery_expires_at = create_credential_delivery(
        user_id=user_id,
        password=password,
        provisioning_uri=totp_data["provisioning_uri"],
        created_at=generated_at,
    )

    # Les identifiants ne sont plus renvoyes directement. Le frontend encode
    # cette URL dans un QR code, consultable une seule fois pendant 10 minutes.
    return {
        "id": user_id,
        "username": username,
        "delivery_token": delivery_token,
        "delivery_url": f"/credentials.html?token={delivery_token}",
        "delivery_expires_at": delivery_expires_at.isoformat(),
        "credentials_expires_at": expires_at.isoformat(),
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
    """Point d'entree HTTP de la fonction create-user."""
    try:
        request_data = parse_request_body(event)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return json_response(400, {"error": "Le corps doit etre un JSON valide."})

    username = str(request_data.get("username", "")).strip()
    if not username:
        return json_response(400, {"error": "Le champ username est obligatoire."})

    try:
        user = create_user(username)
        return json_response(201, user)
    except psycopg.errors.UniqueViolation:
        return json_response(409, {"error": "Ce username existe deja."})
    except requests.RequestException:
        return json_response(502, {"error": "Une fonction OpenFaaS dependante est indisponible."})
    except (KeyError, psycopg.Error):
        return json_response(500, {"error": "La creation du compte a echoue."})




