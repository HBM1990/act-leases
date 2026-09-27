#!/usr/bin/env python3
"""
lease_audit_collector.py — Audit-Chain composition for ACT audit events.

Polls a directory for broker-issued audit events, verifies the broker
signature, and appends a signed, hash-chained audit entry to the local
audit log. The combined log can be verified with `verify_chain()`.

What this collector does:
  1. Polls an audit-bus directory on a configurable interval
  2. For each lease.* audit event, verifies the broker's signature
  3. Appends an audit entry to the local signed, hash-chained audit log
  4. Records the source filename for forensics
  5. Updates a chain-head file so external witnesses can mirror

What this collector does NOT do:
  - Real-time push (configurable poll interval; default 30s)
  - Conflict resolution (later events on same lease_id append in
    arrival order)
  - Witness event emission on the consumer side

Authored 2026-09.
MIT License.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import nacl.signing as ed25519
import nacl.exceptions


# Configuration — paths. Override via env or mount in production.
# All defaults sit under /tmp so a self-test never accidentally writes
# to the working directory or anywhere system-owned.
AUDIT_BUS_DIR = Path(os.environ.get("AUDIT_BUS_DIR", "/tmp/act-leases/audit-bus"))
CONSUMER_AUDIT_LOG = Path(os.environ.get("CONSUMER_AUDIT_LOG", "/tmp/act-leases/audit.log"))
CONSUMER_AUDIT_CHAIN_HEAD = Path(os.environ.get("CONSUMER_AUDIT_CHAIN_HEAD",
                                                "/tmp/act-leases/audit-chain-head"))
CONSUMER_SIGNING_KEY_FILE = Path(os.environ.get("CONSUMER_SIGNING_KEY_FILE",
                                                "/tmp/act-leases/signing.key"))
COLLECTOR_STATE_FILE = Path(os.environ.get("COLLECTOR_STATE_FILE",
                                          "/tmp/act-leases/collector-state.json"))
COLLECTOR_LOG = Path(os.environ.get("COLLECTOR_LOG", "/tmp/act-leases/collector.log"))

# Known broker keys — lazy-register on first verified event.
KNOWN_BROKER_KEYS = {
    "BOOTSTRAP_BROKER_PUBKEY_PLACEHOLDER": "broker-bootstrap",
}

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))


def _log(event: str, detail: dict) -> None:
    COLLECTOR_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **detail,
    }
    with COLLECTOR_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _load_signing_key() -> ed25519.SigningKey:
    if not CONSUMER_SIGNING_KEY_FILE.exists():
        raise RuntimeError(f"signing key not found at {CONSUMER_SIGNING_KEY_FILE}")
    return ed25519.SigningKey(CONSUMER_SIGNING_KEY_FILE.read_bytes())


def _signing_pubkey_hex(sk: ed25519.SigningKey) -> str:
    return bytes(sk.verify_key).hex()


def _read_chain_head() -> str:
    if CONSUMER_AUDIT_CHAIN_HEAD.exists():
        return CONSUMER_AUDIT_CHAIN_HEAD.read_text().strip()
    return "0" * 64


def _write_chain_head(head_hex: str) -> None:
    CONSUMER_AUDIT_CHAIN_HEAD.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONSUMER_AUDIT_CHAIN_HEAD.with_suffix(".tmp")
    tmp.write_text(head_hex)
    tmp.replace(CONSUMER_AUDIT_CHAIN_HEAD)


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True).encode()


def _append_audit_entry(event: str, detail: dict) -> str:
    """Append a signed, hash-chained audit entry.

    Mirrors the canonical audit() structure so verify_chain() works
    on the combined log.
    """
    sk = _load_signing_key()
    prev_hash = _read_chain_head()
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "host": "consumer",
        "prev_hash": prev_hash,
        **detail,
    }
    payload_bytes = _canonical_payload(payload)
    import hashlib
    entry_hash = hashlib.sha256(payload_bytes).hexdigest()
    sig_bytes = sk.sign(payload_bytes).signature
    entry = {
        "payload": payload,
        "entry_hash": entry_hash,
        "sig": sig_bytes.hex(),
    }

    CONSUMER_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with CONSUMER_AUDIT_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    _write_chain_head(entry_hash)
    return entry_hash


def _verify_broker_event(event: dict) -> tuple:
    """Verify broker signature on a lease audit event."""
    if event.get("envelope_type") != "audit_event":
        return False, "wrong-envelope-type"

    pub_hex = event.get("signer_pubkey", "")
    sig_hex = event.get("sig", "")
    if not pub_hex or not sig_hex:
        return False, "missing-pubkey-or-sig"

    # Lazy-register broker keys (verify first, then register)
    if pub_hex not in KNOWN_BROKER_KEYS:
        try:
            payload = {k: v for k, v in event.items() if k not in ("signer_pubkey", "sig")}
            payload_bytes = _canonical_payload(payload)
            pubkey = ed25519.VerifyKey(bytes.fromhex(pub_hex))
            pubkey.verify(payload_bytes, bytes.fromhex(sig_hex))
        except nacl.exceptions.BadSignatureError:
            return False, "bad-sig-unknown-broker"
        except Exception as e:
            return False, f"verify-error:{type(e).__name__}"
        KNOWN_BROKER_KEYS[pub_hex] = "broker (lazy-registered)"

    # Known broker — verify
    try:
        payload = {k: v for k, v in event.items() if k not in ("signer_pubkey", "sig")}
        payload_bytes = _canonical_payload(payload)
        pubkey = ed25519.VerifyKey(bytes.fromhex(pub_hex))
        pubkey.verify(payload_bytes, bytes.fromhex(sig_hex))
    except nacl.exceptions.BadSignatureError:
        return False, "bad-sig"
    except Exception as e:
        return False, f"verify-error:{type(e).__name__}"

    return True, None


def process_one(event_path: Path, processed: set) -> None:
    """Process one broker audit event file."""
    if event_path.name in processed:
        return

    try:
        event = json.loads(event_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        _log("lease.parse.error", {"file": event_path.name, "error": str(e)[:200]})
        processed.add(event_path.name)
        return

    ok, reason = _verify_broker_event(event)
    if not ok:
        _log("lease.verify.fail", {"file": event_path.name, "reason": reason})
        processed.add(event_path.name)
        return

    event_type = event.get("event_type", "")
    if event_type not in ("lease.issued", "lease.revoked"):
        _log("lease.unknown_event_type", {"file": event_path.name, "event_type": event_type})
        processed.add(event_path.name)
        return

    # Verified — append to local audit chain
    detail = {
        "lease_id": event.get("lease_id"),
        "scope": event.get("scope"),
        "ttl": event.get("ttl"),
        "broker_pubkey": event.get("signer_pubkey"),
        "broker_event_file": event_path.name,
        "broker_event_ts": event.get("ts"),
    }
    if event_type == "lease.revoked":
        detail["reason"] = event.get("reason", "unspecified")

    entry_hash = _append_audit_entry(event_type, detail)

    _log("lease.composed", {
        "file": event_path.name,
        "event_type": event_type,
        "lease_id": event.get("lease_id"),
        "entry_hash_prefix": entry_hash[:16],
    })

    processed.add(event_path.name)


def serve_forever() -> None:
    """Poll audit-bus for new broker events."""
    _log("collector.start", {
        "audit_bus_dir": str(AUDIT_BUS_DIR),
        "audit_log": str(CONSUMER_AUDIT_LOG),
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
    })

    processed = set()

    while True:
        if not AUDIT_BUS_DIR.exists():
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        for event_path in AUDIT_BUS_DIR.glob("audit_lease_*.json"):
            if event_path.is_file():
                process_one(event_path, processed)

        time.sleep(POLL_INTERVAL_SECONDS)


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> dict:
    """Test the audit collector end-to-end with a fabricated broker event."""
    import tempfile
    results = []

    with tempfile.TemporaryDirectory(prefix="lease-collector-test-") as tmp:
        tmp_path = Path(tmp)
        bus_dir = tmp_path / "audit-bus"
        bus_dir.mkdir()

        # Generate a test broker key + sign an event
        broker_sk = ed25519.SigningKey.generate()
        broker_pub = bytes(broker_sk.verify_key).hex()

        event = {
            "envelope_type": "audit_event",
            "event_type": "lease.issued",
            "ts": datetime.now(timezone.utc).isoformat(),
            "signer_pubkey": broker_pub,
            "lease_id": "test-lease-001",
            "scope": "/docs/*",
            "ttl": 3600,
            "requested_by": "self-test",
        }
        payload = {k: v for k, v in event.items() if k not in ("signer_pubkey", "sig")}
        payload_bytes = _canonical_payload(payload)
        sig_bytes = broker_sk.sign(payload_bytes).signature
        event["sig"] = sig_bytes.hex()

        event_path = bus_dir / "audit_lease_issued_test.json"
        event_path.write_text(json.dumps(event, indent=2))

        # Patch module paths for this test
        global AUDIT_BUS_DIR, CONSUMER_AUDIT_LOG, CONSUMER_AUDIT_CHAIN_HEAD
        global CONSUMER_SIGNING_KEY_FILE, COLLECTOR_LOG, KNOWN_BROKER_KEYS
        AUDIT_BUS_DIR = bus_dir
        CONSUMER_AUDIT_LOG = tmp_path / "audit.log"
        CONSUMER_AUDIT_CHAIN_HEAD = tmp_path / "chain-head"
        CONSUMER_SIGNING_KEY_FILE = tmp_path / "consumer.key"
        COLLECTOR_LOG = tmp_path / "collector.log"
        # Generate signing key
        sk = ed25519.SigningKey.generate()
        CONSUMER_SIGNING_KEY_FILE.write_bytes(bytes(sk))
        KNOWN_BROKER_KEYS.clear()  # force lazy-register path

        # Process the event
        processed = set()
        process_one(event_path, processed)

        # Verify audit log was appended
        assert CONSUMER_AUDIT_LOG.exists(), "audit log not created"
        log_content = CONSUMER_AUDIT_LOG.read_text().strip()
        assert log_content, "audit log empty"
        consumer_entry = json.loads(log_content)
        assert consumer_entry["payload"]["event"] == "lease.issued", \
            f"Wrong event: {consumer_entry}"
        assert consumer_entry["payload"]["lease_id"] == "test-lease-001", "Wrong lease_id"
        results.append({"test": "process_broker_event", "ok": True})

        # Test bad signature rejection
        bad_event = dict(event)
        bad_event["sig"] = "00" * 64
        bad_path = bus_dir / "audit_lease_issued_bad.json"
        bad_path.write_text(json.dumps(bad_event, indent=2))
        process_one(bad_path, processed)
        log_lines = COLLECTOR_LOG.read_text().strip().split("\n")
        events = [json.loads(l)["event"] for l in log_lines if l]
        assert "lease.verify.fail" in events, f"No verify.fail event: {events}"
        results.append({"test": "reject_bad_signature", "ok": True})

        # Test idempotency
        first_count = len(CONSUMER_AUDIT_LOG.read_text().strip().split("\n"))
        assert event_path.name in processed, "event_path not in processed after first call"
        process_one(event_path, processed)
        second_count = len(CONSUMER_AUDIT_LOG.read_text().strip().split("\n"))
        assert first_count == second_count, f"Re-processing appended: {first_count} -> {second_count}"
        results.append({"test": "idempotent", "ok": True})

    return {
        "tests": results,
        "passed": sum(1 for t in results if t["ok"]),
        "total": len(results),
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["serve", "self-test"])
    args = parser.parse_args()

    if args.mode == "serve":
        serve_forever()
    elif args.mode == "self-test":
        result = _self_test()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["passed"] == result["total"] else 1)
