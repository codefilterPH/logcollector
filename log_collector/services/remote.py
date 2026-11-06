import requests


class RemoteCollectorError(Exception):
    pass


def fetch_remote_json(entity, resource, params=None):
    try:
        return fetch_remote_response(entity, resource, params=params).json()
    except (requests.RequestException, ValueError) as exc:
        raise RemoteCollectorError(str(exc)) from exc


def fetch_remote_response(entity, resource, params=None):
    if not entity.api_base_url or not entity.remote_api_key:
        raise RemoteCollectorError("This integration has no endpoint URL or API key configured.")
    url = (
        f"{entity.api_base_url.rstrip('/')}/log-collector/api/entities/"
        f"{entity.remote_entity_slug}/{resource.lstrip('/')}"
    )
    try:
        response = requests.get(
            url,
            headers={"X-Api-Key": entity.remote_api_key},
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        return response
    except requests.RequestException as exc:
        raise RemoteCollectorError(str(exc)) from exc
