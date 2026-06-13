import hashlib
import json
import os
from datetime import datetime, timezone

import psycopg
from cryptography.fernet import Fernet, InvalidToken


def parse_request_body(event):
    """Extrait le JSON envoye a la fonction par OpenFaaS."""
    raw_body = event.body if hasattr(event, "body") else event

    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8")

    if isinstance(raw_body, str):
        return json.loads(raw_body or "{}")

    return raw_body or {}


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


def hash_delivery_token(token):
    """Calcule l'empreinte SHA-256 stockee en base a la place du jeton brut."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def decrypt_value(ciphertext):
    """Dechiffre une valeur avec la cle de remise stockee dans Kubernetes."""
    encryption_key = read_secret("credential-delivery-key").encode("ascii")
    return Fernet(encryption_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")


def redeem_credentials(token, now=None):
    """Consomme un jeton une seule fois et retourne les identifiants temporaires."""
    token_hash = hash_delivery_token(token)
    current_time = now or datetime.now(timezone.utc)

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            # FOR UPDATE verrouille la ligne pendant la transaction. Deux appels
            # simultanes ne peuvent donc pas consommer le meme jeton.
            cursor.execute(
                """
                SELECT
                    cd.id,
                    u.username,
                    cd.password_ciphertext,
                    cd.provisioning_uri_ciphertext,
                    cd.expires_at,
                    cd.used_at
                FROM credential_deliveries cd
                JOIN users u ON u.id = cd.user_id
                WHERE cd.token_hash = %s
                FOR UPDATE
                """,
                (token_hash,),
            )
            row = cursor.fetchone()

            if row is None:
                return 404, {"error": "Lien de remise invalide."}

            delivery_id, username, password_ciphertext, uri_ciphertext, expires_at, used_at = row

            if used_at is not None:
                return 410, {"error": "Ces identifiants ont deja ete consultes."}

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if current_time >= expires_at:
                return 410, {"error": "Le lien de remise a expire."}

            # La ligne est marquee comme utilisee avant la validation de la transaction.
            cursor.execute(
                "UPDATE credential_deliveries SET used_at = %s WHERE id = %s",
                (current_time, delivery_id),
            )

        connection.commit()

    try:
        password = decrypt_value(password_ciphertext)
        provisioning_uri = decrypt_value(uri_ciphertext)
    except InvalidToken:
        return 500, {"error": "Les identifiants temporaires sont illisibles."}

    return 200, {
        "username": username,
        "password": password,
        "provisioning_uri": provisioning_uri,
        "used_at": current_time.isoformat(),
    }


def json_response(status_code, body):
    """Construit une reponse HTTP JSON comprise par OpenFaaS."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handle(event, context):
    """Point d'entree HTTP de la fonction redeem-credentials."""
    try:
        request_data = parse_request_body(event)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return json_response(400, {"error": "Le corps doit etre un JSON valide."})

    token = str(request_data.get("token", "")).strip()
    if not token:
        return json_response(400, {"error": "Le champ token est obligatoire."})

    try:
        status_code, body = redeem_credentials(token)
        return json_response(status_code, body)
    except psycopg.Error:
        return json_response(500, {"error": "La lecture des identifiants a echoue."})
