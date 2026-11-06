import base64
import hashlib
from urllib.parse import urlsplit

import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

from .models import CrowdSecConnection


class CrowdSecError(Exception):
    pass


def _fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_password(password):
    return _fernet().encrypt(password.encode()).decode()


def _password(connection):
    try:
        return _fernet().decrypt(connection.encrypted_password.encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise CrowdSecError("Saved credential cannot be decrypted. Re-enter the CrowdSec credential.") from exc


def _url(api_url, path):
    parsed = urlsplit(api_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise CrowdSecError("Enter a valid CrowdSec Local API URL.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise CrowdSecError("CrowdSec connections must use HTTPS except for loopback development.")
    return f"{api_url.rstrip('/')}/{path.lstrip('/')}"


def request(connection, method, path, **kwargs):
    try:
        login = requests.post(
            _url(connection.api_url, "v1/watchers/login"),
            json={"machine_id": connection.machine_id, "password": _password(connection)},
            timeout=8,
        )
        login.raise_for_status()
        token = login.json().get("token")
        if not token:
            raise CrowdSecError("CrowdSec returned no session token.")
        response = requests.request(
            method, _url(connection.api_url, path),
            headers={"Authorization": f"Bearer {token}"}, timeout=8, **kwargs,
        )
        response.raise_for_status()
        return response.json() if response.content else {}
    except CrowdSecError:
        raise
    except (requests.RequestException, ValueError) as exc:
        raise CrowdSecError("CrowdSec connection failed. Check the URL, credentials, and LAPI permissions.") from exc


def validate_connection(api_url, machine_id, password):
    class Candidate:
        pass
    candidate = Candidate()
    candidate.api_url, candidate.machine_id = api_url, machine_id
    candidate.encrypted_password = encrypt_password(password)
    request(candidate, "GET", "v1/alerts?limit=1")
