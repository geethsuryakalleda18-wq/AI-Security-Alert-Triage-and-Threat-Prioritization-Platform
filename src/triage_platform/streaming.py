from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator

from .models import SecurityEvent


@dataclass(frozen=True)
class RedisStreamConfig:
    url: str
    stream: str = "security-events"
    batch_size: int = 100
    start_id: str = "0-0"


def consume_redis_stream(config: RedisStreamConfig) -> Iterator[list[SecurityEvent]]:
    try:
        import redis
    except ImportError as exc:
        raise RuntimeError("Install redis support with: python3 -m pip install redis") from exc

    client = redis.Redis.from_url(config.url, decode_responses=True)
    last_id = config.start_id
    while True:
        batches = client.xread({config.stream: last_id}, count=config.batch_size, block=5000)
        for _, messages in batches:
            events: list[SecurityEvent] = []
            for message_id, fields in messages:
                last_id = message_id
                payload = fields.get("event") or fields.get("payload") or json.dumps(fields)
                events.append(SecurityEvent.from_dict(json.loads(payload)))
            if events:
                yield events
