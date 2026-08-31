"""Unit tests for the standard-library Pub/Sub REST adapter."""

from __future__ import annotations

import base64
import json

from bantam.pubsub import MetadataTokenProvider, PubSubClient


class Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


def test_pubsub_publish_encodes_message_and_attributes() -> None:
    requests = []

    def opener(request, *, timeout):
        requests.append((request, timeout, json.loads(request.data)))
        return Response({"messageIds": ["pubsub-message-1"]})

    client = PubSubClient(
        "bantam-demo",
        token_provider=MetadataTokenProvider(static_token="token-1"),
        opener=opener,
    )

    message_id = client.publish(
        "bantam-events",
        b'{"event_id":"event-1"}',
        {"event_type": "payment.transfer_posted.v1", "event_id": "event-1"},
    )

    request, timeout, body = requests[0]
    assert message_id == "pubsub-message-1"
    assert timeout == 10
    assert request.full_url.endswith(
        "/projects/bantam-demo/topics/bantam-events:publish"
    )
    assert request.headers["Authorization"] == "Bearer token-1"
    assert base64.b64decode(body["messages"][0]["data"]) == b'{"event_id":"event-1"}'
    assert body["messages"][0]["attributes"]["event_type"] == (
        "payment.transfer_posted.v1"
    )


def test_pubsub_pull_decodes_messages_and_acknowledges() -> None:
    calls = []

    def opener(request, *, timeout):
        calls.append((request, json.loads(request.data)))
        if request.full_url.endswith(":pull"):
            return Response(
                {
                    "receivedMessages": [
                        {
                            "ackId": "ack-1",
                            "message": {
                                "messageId": "message-1",
                                "data": base64.b64encode(b'{"ok":true}').decode(),
                                "attributes": {"event_type": "payment"},
                            },
                        }
                    ]
                }
            )
        return Response({})

    client = PubSubClient(
        "bantam-demo",
        token_provider=MetadataTokenProvider(static_token="token-1"),
        opener=opener,
    )

    messages = client.pull("risk-worker", 5)
    client.acknowledge("risk-worker", [messages[0].ack_id])

    assert messages[0].data == b'{"ok":true}'
    assert messages[0].attributes == {"event_type": "payment"}
    assert messages[0].message_id == "message-1"
    assert calls[0][0].full_url.endswith(
        "/projects/bantam-demo/subscriptions/risk-worker:pull"
    )
    assert calls[0][1] == {"maxMessages": 5}
    assert calls[1][0].full_url.endswith(":acknowledge")
    assert calls[1][1] == {"ackIds": ["ack-1"]}
