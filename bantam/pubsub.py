"""Google Pub/Sub REST adapter for Cloud Run event jobs.

The project keeps the local developer stack on NATS JetStream, but GCP should
not pretend to use NATS while Terraform provisions Pub/Sub.  This module uses
only the Python standard library so the core app image does not need an
additional Google client dependency.  In Cloud Run it gets an OAuth token from
the metadata server and calls the Pub/Sub JSON API over HTTPS.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol


PUBSUB_API_ROOT = "https://pubsub.googleapis.com/v1"
METADATA_CREDENTIAL_ENDPOINT = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)


class PubSubError(RuntimeError):
    """Raised when Pub/Sub rejects a publish, pull, or ack request."""


class TokenProvider(Protocol):
    def token(self) -> str:
        """Return an OAuth bearer token usable with the Pub/Sub API."""


class ResponseContext(Protocol):
    def __enter__(self) -> "ResponseContext": ...

    def __exit__(self, exc_type, exc, traceback) -> bool | None: ...

    def read(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PubSubMessage:
    ack_id: str
    data: bytes
    attributes: dict[str, str]
    message_id: str


class MetadataTokenProvider:
    """Fetch and cache the Cloud Run metadata-server access token."""

    def __init__(self, *, static_token: str | None = None) -> None:
        self.static_token = static_token
        self._token: str | None = None
        self._expires_at = 0.0

    def token(self) -> str:
        if self.static_token:
            return self.static_token
        now = time.monotonic()
        if self._token and now < self._expires_at - 60:
            return self._token

        request = urllib.request.Request(
            METADATA_CREDENTIAL_ENDPOINT,
            headers={"Metadata-Flavor": "Google"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=2) as response:  # nosec B310
            payload = json.loads(response.read())
        self._token = str(payload["access_token"])
        self._expires_at = now + int(payload.get("expires_in", 300))
        return self._token


class PubSubClient:
    """Small blocking Pub/Sub JSON client wrapped by async services."""

    def __init__(
        self,
        project_id: str,
        *,
        token_provider: TokenProvider | None = None,
        opener=urllib.request.urlopen,
        timeout_seconds: int = 10,
    ) -> None:
        self.project_id = project_id
        self.token_provider = token_provider or MetadataTokenProvider()
        self.opener = opener
        self.timeout_seconds = timeout_seconds

    def publish(
        self, topic: str, data: bytes, attributes: dict[str, str] | None = None
    ) -> str:
        body = {
            "messages": [
                {
                    "data": base64.b64encode(data).decode("ascii"),
                    "attributes": attributes or {},
                }
            ]
        }
        result = self._request(self._topic_path(topic), "publish", body)
        message_ids = result.get("messageIds", [])
        if not message_ids:
            raise PubSubError("Pub/Sub publish response did not include messageIds")
        return str(message_ids[0])

    def pull(self, subscription: str, max_messages: int) -> list[PubSubMessage]:
        result = self._request(
            self._subscription_path(subscription),
            "pull",
            {"maxMessages": max_messages},
        )
        messages: list[PubSubMessage] = []
        for received in result.get("receivedMessages", []):
            raw_message = received["message"]
            messages.append(
                PubSubMessage(
                    ack_id=str(received["ackId"]),
                    data=base64.b64decode(raw_message.get("data", ""), validate=True),
                    attributes={
                        str(key): str(value)
                        for key, value in raw_message.get("attributes", {}).items()
                    },
                    message_id=str(raw_message.get("messageId", "")),
                )
            )
        return messages

    def acknowledge(self, subscription: str, ack_ids: list[str]) -> None:
        if not ack_ids:
            return
        self._request(
            self._subscription_path(subscription),
            "acknowledge",
            {"ackIds": ack_ids},
        )

    def _request(
        self, resource_path: str, method: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        encoded_path = urllib.parse.quote(resource_path, safe="/")
        url = f"{PUBSUB_API_ROOT}/{encoded_path}:{method}"
        request = urllib.request.Request(
            url,
            data=json.dumps(body, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self.token_provider.token()}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self.opener(  # nosec B310
                request, timeout=self.timeout_seconds
            ) as response:
                payload = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:1000]
            raise PubSubError(
                f"Pub/Sub {method} failed with HTTP {error.code}: {detail}"
            ) from error
        if not payload:
            return {}
        return json.loads(payload)

    def _topic_path(self, topic: str) -> str:
        if topic.startswith("projects/"):
            return topic
        return f"projects/{self.project_id}/topics/{topic}"

    def _subscription_path(self, subscription: str) -> str:
        if subscription.startswith("projects/"):
            return subscription
        return f"projects/{self.project_id}/subscriptions/{subscription}"
