"""
Sentinel-Core Event Forwarder — Redis Publisher

Publishes transformed Sentinel events to a Redis Stream.
Falls back to stdout logging if Redis is unavailable.
"""

import json
import logging

import redis

from .config import Config

logger = logging.getLogger("sentinel.publisher")


class EventPublisher:
    """Publishes Sentinel events to Redis Streams with stdout fallback."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._redis: redis.Redis | None = None
        self._connected = False
        self._connect()

    def _connect(self) -> None:
        """Attempt to connect to Redis."""
        try:
            self._redis = redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                db=self.config.REDIS_DB,
                password=self.config.REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=3,
                retry_on_timeout=True,
            )
            self._redis.ping()
            self._connected = True
            logger.info(
                "✅ Connected to Redis at %s:%d",
                self.config.REDIS_HOST,
                self.config.REDIS_PORT,
            )
        except (redis.ConnectionError, redis.TimeoutError) as e:
            self._connected = False
            logger.warning(
                "⚠️  Redis unavailable (%s). Falling back to stdout.", e
            )

    @property
    def is_connected(self) -> bool:
        return self._connected

    def publish(self, event: dict) -> str | None:
        """
        Publish an event to the Redis stream.

        Returns the stream message ID on success, or None on fallback/failure.
        """
        event_json = json.dumps(event, default=str)

        # Try Redis first
        if self._connected and self._redis is not None:
            try:
                msg_id = self._redis.xadd(
                    self.config.REDIS_STREAM_KEY,
                    {"event": event_json},
                    maxlen=self.config.REDIS_MAXLEN,
                )
                logger.debug("Published event %s → Redis stream ID %s", event.get("event_id"), msg_id)
                return msg_id
            except (redis.ConnectionError, redis.TimeoutError) as e:
                logger.warning("Redis publish failed (%s). Falling back to stdout.", e)
                self._connected = False

        # Fallback: stdout
        print(event_json, flush=True)
        return None

    def close(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            try:
                self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._connected = False
