"""
Live agent-activity feed -- the Python half of V1 ("view what each agent is
doing").

The iterative agent already emits per-step callbacks and single-shot agents have
their own Java-side progress panels, but there was no ONE place a UI could
subscribe to and watch the whole harness work in real time -- routing, each
specialist finishing, validators running, the deterministic scans, chain
detection. This is that place: a small, process-wide, append-only feed of
activity events with monotonic sequence numbers, which the Burp panel polls
(`GET /activity?since=<seq>`) to render a live view.

Deliberately tiny and dependency-free:

  - A bounded ring buffer (a deque with maxlen), so it can never grow without
    limit no matter how long a session runs -- old events fall off the back.
  - A monotonic sequence number per event, so a poller asks "everything after N"
    and never misses or double-counts, even though the buffer itself is bounded
    (if the poller falls far enough behind that events aged out, `since()` says
    so via the returned `dropped` count rather than silently skipping).
  - Publishing NEVER raises into the caller: the feed is observability, and a
    telemetry buffer must never be able to break the analysis it's observing.

Thread-safe (a plain lock); publish from sync or async code alike.
"""
from __future__ import annotations
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class ActivityEvent:
    seq: int
    ts: float
    kind: str                 # analysis_start | dispatch | agent_done | validation | scan | chain | iterative_step | analysis_done | note
    message: str
    agent: str = ""
    level: str = "info"       # info | warn | error
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"seq": self.seq, "ts": self.ts, "kind": self.kind, "message": self.message,
                "agent": self.agent, "level": self.level, "detail": self.detail}


class ActivityFeed:
    def __init__(self, maxlen: int = 500):
        self._buf: deque[ActivityEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def publish(self, kind: str, message: str, *, agent: str = "", level: str = "info",
                **detail) -> ActivityEvent | None:
        """Append an event and return it. Never raises into the caller -- on any
        internal error it returns None and the observed work carries on."""
        try:
            with self._lock:
                self._seq += 1
                ev = ActivityEvent(seq=self._seq, ts=time.time(), kind=kind,
                                   message=message, agent=agent, level=level, detail=detail)
                self._buf.append(ev)
                return ev
        except Exception:
            return None

    def since(self, seq: int) -> dict:
        """Events with seq > `seq`, plus the current latest seq and how many
        events were dropped from the buffer before the caller's position (so a
        slow poller can tell it missed some rather than silently skipping)."""
        with self._lock:
            latest = self._seq
            events = [e for e in self._buf if e.seq > seq]
            oldest = self._buf[0].seq if self._buf else latest + 1
            # If the caller asked for everything after `seq` but the oldest event
            # we still hold is more than one past `seq`, the gap aged out.
            dropped = max(0, oldest - (seq + 1)) if seq + 1 < oldest and events else 0
        return {"latest_seq": latest, "dropped": dropped,
                "events": [e.to_dict() for e in events]}

    def snapshot(self, limit: int = 100) -> dict:
        with self._lock:
            latest = self._seq
            events = list(self._buf)[-limit:]
        return {"latest_seq": latest, "events": [e.to_dict() for e in events]}

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()


# Process-wide singleton every publisher and the /activity endpoint share.
feed = ActivityFeed()


def publish(kind: str, message: str, **kw) -> "ActivityEvent | None":
    return feed.publish(kind, message, **kw)


def since(seq: int) -> dict:
    return feed.since(seq)


def snapshot(limit: int = 100) -> dict:
    return feed.snapshot(limit)
