"""Typed HTTP client for Phase 1 Kiln Core endpoints."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class Status:
    installation_id: str
    provider_mode: str
    mutation_enabled: bool
    persistence: str


@dataclass(frozen=True)
class Resource:
    id: str
    installation_id: str
    project_id: str
    type: str
    ownership: str
    state: str
    provider_id: str
    provider_resource_id: str
    provider_kind: str
    node: str | None
    pool: str | None
    created_by: str
    created_at: str
    expires_at: str | None
    profile: str | None


class KilnApiError(Exception):
    """A sanitized Kiln Core API failure."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"Kiln API request failed ({code})")
        self.status = status
        self.code = code


class _RejectRedirects(HTTPRedirectHandler):
    """Turn every redirect into an HTTPError before urllib sends another request."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class KilnClient:
    """A synchronous client for Kiln Core. Keep the token in trusted code."""

    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 15.0) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("base_url must be an HTTP(S) origin without credentials, path, query, or fragment")
        if not token:
            raise ValueError("token is required")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._opener = build_opener(_RejectRedirects())

    def status(self) -> Status:
        return _status(self._request("GET", "/v1/status"))

    def resources(self) -> list[Resource]:
        body = self._request("GET", "/v1/resources")
        return [_resource(item) for item in body["resources"]]

    def resource(self, resource_id: str) -> Resource:
        return _resource(self._request("GET", f"/v1/resources/{quote(resource_id, safe='')}"))

    def inventory(self) -> Mapping[str, Any]:
        return self._request("GET", "/v1/inventory")

    def create_development(self, *, ttl_seconds: int, idempotency_key: str, project_id: str = "default", profile: str | None = None) -> Resource:
        payload: dict[str, Any] = {"type": "development", "projectId": project_id, "ttlSeconds": ttl_seconds}
        if profile is not None:
            payload["profile"] = profile
        return _resource(self._request("POST", "/v1/resources", payload, {"Idempotency-Key": idempotency_key}))

    def stop_resource(self, resource_id: str) -> Resource:
        return _resource(self._request("POST", f"/v1/resources/{quote(resource_id, safe='')}/stop", {}))

    def destroy_resource(self, resource_id: str) -> Resource:
        return _resource(self._request("DELETE", f"/v1/resources/{quote(resource_id, safe='')}"))

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None = None, headers: Mapping[str, str] | None = None) -> Mapping[str, Any]:
        encoded = json.dumps(body).encode() if body is not None else None
        request = Request(
            f"{self._base_url}{path}",
            data=encoded,
            method=method,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self._token}", **({"Content-Type": "application/json"} if encoded else {}), **(headers or {})},
        )
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                return json.loads(response.read())
        except HTTPError as error:
            raise KilnApiError(error.code, _error_code(error)) from None
        except (URLError, TimeoutError) as error:
            raise KilnApiError(0, "request_failed") from error


def _error_code(error: HTTPError) -> str:
    try:
        body = json.loads(error.read())
        code = body.get("error", {}).get("code")
        return code if isinstance(code, str) and code in _KNOWN_ERROR_CODES else "request_failed"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "request_failed"


def _status(value: Mapping[str, Any]) -> Status:
    return Status(value["installationId"], value["providerMode"], value["mutationEnabled"], value["persistence"])


def _resource(value: Mapping[str, Any]) -> Resource:
    return Resource(
        id=value["id"], installation_id=value["installationId"], project_id=value["projectId"], type=value["type"], ownership=value["ownership"], state=value["state"], provider_id=value["providerId"], provider_resource_id=value["providerResourceId"], provider_kind=value["providerKind"], node=value.get("node"), pool=value.get("pool"), created_by=value["createdBy"], created_at=value["createdAt"], expires_at=value.get("expiresAt"), profile=value.get("profile"),
    )


_KNOWN_ERROR_CODES = frozenset({
    "CONFLICT", "IDEMPOTENCY_CONFLICT", "INTERNAL", "INVALID_INPUT", "NOT_FOUND", "PROVIDER_FAILURE",
    "SAFETY_DENIED", "UNAUTHENTICATED", "UNAUTHORIZED", "UNSUPPORTED",
})
