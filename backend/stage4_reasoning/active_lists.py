"""
Wazuh-style Active Lists: runtime-updated lookup tables that rules check
against, and that convictions automatically feed back into. This is what
gets you "seen this exact threat before" for free, without re-running the
whole pipeline on a repeat sample.

Backed by a flat JSON file for now (zero deployment cost). Swap
`JSONActiveLists` for a Django-model-backed version later -- the interface
(`is_known_bad`, `record_verdict`) doesn't need to change, so nothing above
this layer (rules.py, agent.py) has to know the storage changed.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ActiveListEntry:
    value: str
    verdict: str
    confidence: float
    first_added: str
    hit_count: int = 0


class JSONActiveLists:
    """
    Three lists, same pattern as Wazuh's rule-populated lookup tables:
      - hashes:   sha256 -> verdict   (exact repeat sample)
      - packages: package_name -> verdict  (same app, different build/hash)
      - iocs:     url/domain/ip -> verdict  (shared infra across samples)
    """

    def __init__(self, path: str | os.PathLike = "stage4_active_lists.json"):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, dict]] = {"hashes": {}, "packages": {}, "iocs": {}}
        if self.path.exists():
            self._data.update(json.loads(self.path.read_text()))

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2))

    def _lookup(self, list_name: str, key: str) -> ActiveListEntry | None:
        raw = self._data[list_name].get(key)
        return ActiveListEntry(**raw) if raw else None

    def is_known_bad(self, *, sha256: str | None = None, package_name: str | None = None,
                      iocs: list[str] | None = None) -> ActiveListEntry | None:
        """First match wins: exact hash > package name > shared IOC infra."""
        if sha256:
            hit = self._lookup("hashes", sha256)
            if hit and hit.verdict in ("malicious", "suspicious"):
                return hit
        if package_name:
            hit = self._lookup("packages", package_name)
            if hit and hit.verdict in ("malicious", "suspicious"):
                return hit
        for ioc in iocs or []:
            hit = self._lookup("iocs", ioc)
            if hit and hit.verdict in ("malicious", "suspicious"):
                return hit
        return None

    def record_verdict(self, *, sha256: str, package_name: str, verdict: str,
                        confidence: float, iocs: list[str] | None = None) -> None:
        """Called once a Stage-4 verdict is final. Only convictions worth
        remembering get written back -- an 'unknown' verdict doesn't pollute
        the list with noise."""
        if verdict not in ("malicious", "suspicious", "benign"):
            return
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            for list_name, key in (("hashes", sha256), ("packages", package_name)):
                existing = self._data[list_name].get(key)
                if existing:
                    existing["hit_count"] += 1
                    existing["verdict"] = verdict
                    existing["confidence"] = confidence
                else:
                    self._data[list_name][key] = {
                        "value": key, "verdict": verdict, "confidence": confidence,
                        "first_added": now, "hit_count": 1,
                    }
            for ioc in iocs or []:
                if verdict in ("malicious", "suspicious"):
                    existing = self._data["iocs"].get(ioc)
                    if existing:
                        existing["hit_count"] += 1
                    else:
                        self._data["iocs"][ioc] = {
                            "value": ioc, "verdict": verdict, "confidence": confidence,
                            "first_added": now, "hit_count": 1,
                        }
            self._save()


@dataclass
class DeviceEvent:
    device_id: str
    level: int
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CorrelationWindow:
    """
    Wazuh-style frequency rule: N events of severity >= threshold from the
    same device within a time window escalates, even if each event alone
    didn't clear the bar. In-memory is fine here -- this is a rolling
    short-term window, not something that needs to survive a restart.
    """

    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self._events: dict[str, list[DeviceEvent]] = {}

    def record(self, device_id: str, level: int) -> None:
        self._events.setdefault(device_id, []).append(DeviceEvent(device_id, level))

    def count_since(self, device_id: str, min_level: int) -> int:
        now = datetime.now(timezone.utc)
        events = self._events.get(device_id, [])
        fresh = [
            e for e in events
            if (now - datetime.fromisoformat(e.at)).total_seconds() <= self.window_seconds
            and e.level >= min_level
        ]
        self._events[device_id] = fresh
        return len(fresh)
