"""
CyberShield - Evidence hashing utility
======================================

Cryptographic chain-of-custody helper for investigations: SHA-256 hashes of
evidence artifacts (PCAP files, alert details, incident exports). Demonstrates
how analysts prove that evidence has not been altered.
"""

import hashlib
import json
import os

from backend.utils.helpers import safe_json_dumps


def hash_file(path: str) -> str:
    """SHA-256 of a file, streamed in chunks (works for large PCAPs)."""
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 256), b""):
            sha.update(chunk)
    return sha.hexdigest()


def hash_alert(alert) -> str:
    """SHA-256 over an alert's canonical fields."""
    canonical = {
        "id": alert.id, "type": alert.alert_type, "severity": alert.severity,
        "source_ip": alert.source_ip, "destination_ip": alert.destination_ip,
        "reason": alert.reason, "created_at": str(alert.created_at),
        "details": safe_json_dumps(alert.details_json),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def hash_incident(incident) -> str:
    """SHA-256 over the incident and its full timeline."""
    canonical = {
        "ref": incident.incident_ref, "title": incident.title,
        "severity": incident.severity, "status": incident.status,
        "created_at": str(incident.created_at),
        "events": [{"type": e.event_type, "msg": e.message,
                    "actor": e.actor, "at": str(e.created_at)}
                   for e in incident.events],
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def file_info(path: str) -> dict:
    """Convenience: size + sha256 + basename for one evidence file."""
    return {
        "filename": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "sha256": hash_file(path),
    }
