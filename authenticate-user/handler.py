import json
import os
from datetime import datetime, timezone

import bcrypt
import psycopg
import pyotp
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


def encrypt_mfa_secret(mfa_secret):
    """Chiffre un secret TOTP avec la cle applicative Kubernetes."""
    encryption_key = read_secret("credential-delivery-key").encode("ascii")
    return Fernet(encryption_key).encrypt(mfa_secret.encode("utf-8")).decode("ascii")


def decrypt_mfa_secret(stored_secret):
    """Dechiffre le secret TOTP et reconnait les anciennes valeurs en clair."""
    encryption_key = read_secret("credential-delivery-key").encode("ascii")
    try:
        clear_secret = Fernet(encryption_key).decrypt(
            stored_secret.encode("ascii")
        ).decode("utf-8")
        return clear_secret, False
    except (InvalidToken, UnicodeEncodeError):
        # Compatibilite transitoire avec les comptes crees avant le chiffrement.
        return stored_secret, True


def get_user_by_username(username):
    """Retourne les donnees de securite d'un utilisateur ou None."""
    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, password_hash, mfa_secret, expires_at, active
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
            row = cursor.fetchone()

    if row is None:
        return None

    return {
        "id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "mfa_secret": row[3],
        "expires_at": row[4],
        "active": row[5],
    }


def activate_user(user_id):
    """Active le compte apres la premiere authentification complete."""
    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET active = TRUE WHERE id = %s",
                (user_id,),
            )
        connection.commit()


def migrate_legacy_mfa_secret(user_id, mfa_secret):
    """Remplace un ancien secret en clair apres authentification reussie."""
    encrypted_secret = encrypt_mfa_secret(mfa_secret)
    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET mfa_secret = %s WHERE id = %s",
                (encrypted_secret, user_id),
            )
        connection.commit()


def verify_password(password, password_hash):
    """Compare le mot de passe fourni avec son hash bcrypt."""
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


def verify_totp(totp_code, mfa_secret):
    """Verifie le code TOTP avec une tolerance d'une periode de 30 secondes."""
    return pyotp.TOTP(mfa_secret).verify(totp_code, valid_window=1)


def authenticate(username, password, totp_code, now=None):
    """Applique toutes les regles d'authentification COFRAP."""
    user = get_user_by_username(username)
    if user is None:
        return 401, {"error": "Identifiants invalides."}

    if not verify_password(password, user["password_hash"]):
        return 401, {"error": "Identifiants invalides."}

    mfa_secret, is_legacy_secret = decrypt_mfa_secret(user["mfa_secret"])
    if not verify_totp(totp_code, mfa_secret):
        return 401, {"error": "Code TOTP invalide."}

    current_time = now or datetime.now(timezone.utc)
    expires_at = user["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if current_time >= expires_at:
        return 403, {"error": "Les identifiants ont expire et doivent etre renouveles."}

    if is_legacy_secret:
        migrate_legacy_mfa_secret(user["id"], mfa_secret)

    # La premiere authentification avec mot de passe + TOTP active le compte.
    if not user["active"]:
        activate_user(user["id"])

    return 200, {
        "authenticated": True,
        "user_id": user["id"],
        "username": user["username"],
        "active": True,
        "expires_at": expires_at.isoformat(),
    }


def json_response(status_code, body):
    """Construit une reponse HTTP JSON comprise par OpenFaaS."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handle(event, context):
    """Point d'entree HTTP de la fonction authenticate-user."""
    try:
        request_data = parse_request_body(event)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return json_response(400, {"error": "Le corps doit etre un JSON valide."})

    username = str(request_data.get("username", "")).strip()
    password = str(request_data.get("password", ""))
    totp_code = str(request_data.get("totp_code", "")).strip()

    if not username or not password or not totp_code:
        return json_response(
            400,
            {"error": "Les champs username, password et totp_code sont obligatoires."},
        )

    try:
        status_code, body = authenticate(username, password, totp_code)
        return json_response(status_code, body)
    except (ValueError, psycopg.Error):
        return json_response(500, {"error": "L'authentification a echoue."})
