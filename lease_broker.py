#!/usr/bin/env python3
"""
lease_broker.py — ACT root-lease broker.

This broker issues root leases (signed with the broker's signing key)
and emits signed audit events for every issuance and revocation.
Holders attenuate client-side; consumers verify with act_verify.py.

What this broker does:
  1. Listens on a Unix socket
  2. Accepts issuance requests over the socket
  3. Issues root leases signed with the broker's Ed25519 key
  4. Drops the signed root lease to a leases directory (atomic write)
  5. Logs issuance as a signed audit event
  6. Logs issuance as a witness entry (composes with watchdog/witness)

What this broker does NOT do:
  - Network protocols (Unix socket only — extend for your transport)
  - Sub-lease issuance (holders attenuate client-side)
  - Witness receipt verification on incoming chains (handled by verifier)

Authored 2026-09.
MIT License.
"""

import hashlib
import json
import os
import secrets
import socket
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import nacl.signing as ed25519
import nacl.exceptions


# Configuration — paths. Override via env or mount in production.
# All defaults sit under /tmp so a self-test never accidentally writes
# to the working directory or anywhere system-owned.
BROKER_SOCK = Path(os.environ.get("BROKER_SOCK", "/tmp/act-leases/broker.sock"))
EXCHANGE_LEASE_DIR = Path(os.environ.get("EXCHANGE_LEASE_DIR", "/tmp/act-leases/leases"))
EXCHANGE_AUDIT_DIR = Path(os.environ.get("EXCHANGE_AUDIT_DIR", "/tmp/act-leases/audit-bus"))
WITNESS_LOG = Path(os.environ.get("WITNESS_LOG", "/tmp/act-leases/heartbeat.log"))

# Broker signing key. Production: HSM-backed. Dev: file with 0o600 perms.
BROKER_KEY_FILE = Path(os.environ.get("BROKER_KEY_FILE", "/tmp/act-leases/broker-signing.key"))

# Trust store — broker is the root authority. Lazy-register holders.
TRUSTED_SIGNERS = {
    "BOOTSTRAP_BROKER_PUBKEY_PLACEHOLDER": "broker-bootstrap",
}

DEFAULT_TTL_SECONDS = 3600


def _load_or_create_broker_key() -> ed25519.SigningKey:
    """Load broker signing key from disk, or generate one."""
    if BROKER_KEY_FILE.exists():
        seed = BROKER_KEY_FILE.read_bytes()
        return ed25519.SigningKey(seed)
    BROKER_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    sk = ed25519.SigningKey.generate()
    BROKER_KEY_FILE.write_bytes(bytes(sk))
    os.chmod(BROKER_KEY_FILE, 0o600)
    return sk


def _broker_pubkey_hex(sk: ed25519.SigningKey) -> str:
    return bytes(sk.verify_key).hex()


def _canonical_payload(lease: dict) -> bytes:
    """Canonical JSON for signing/verification."""
    return json.dumps(lease, sort_keys=True).encode()


def _audit_event(event_type: str, detail: dict) -> dict:
    """Build a signed audit event.

    Returns the full envelope with signer_pubkey (hex) + sig. Downstream
    audit collectors verify this signature before accepting.
    """
    sk = _broker_sk()
    pub_hex = _broker_pubkey_hex(sk)

    payload = {
        "envelope_type": "audit_event",
        "event_type": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
        **detail,
    }
    payload_bytes = _canonical_payload(payload)
    sig_bytes = sk.sign(payload_bytes).signature

    return {
        **payload,
        "signer_pubkey": pub_hex,
        "sig": sig_bytes.hex(),
    }


def _drop_to_exchange(filename_prefix: str, payload: dict, target_dir: Path) -> Path:
    """Atomic write: write to .tmp, rename."""
    target_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat().replace(":", "").replace("+", "_").replace(".", "_")
    out = target_dir / f"{filename_prefix}_{ts}.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(out)
    return out


def issue_root_lease(scope: str, ttl: int = DEFAULT_TTL_SECONDS,
                     requested_by: str = "anonymous") -> dict:
    """Issue a root lease, signed with the broker's Ed25519 key.

    Args:
        scope: path prefix or scope expression, e.g. "/docs/*"
        ttl: seconds until expiry
        requested_by: who asked — recorded in audit

    Returns:
        The signed root lease dict, also dropped to the leases dir.
    """
    sk = _load_or_create_broker_key()
    pub_hex = _broker_pubkey_hex(sk)

    if pub_hex not in TRUSTED_SIGNERS:
        TRUSTED_SIGNERS[pub_hex] = "broker-active"

    lease_id = f"root-{secrets.token_hex(6)}"
    issued_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "id": lease_id,
        "scope": scope,
        "ttl": ttl,
        "issued_at": issued_at,
        "parent": None,
        "restriction": None,
        "chain_hash_at_issuance": None,
    }
    payload_bytes = _canonical_payload(payload)
    sig_bytes = sk.sign(payload_bytes).signature

    lease = {
        **payload,
        "signer_pubkey": pub_hex,
        "sig": sig_bytes.hex(),
    }

    # Drop signed lease
    lease_path = _drop_to_exchange(f"lease_{lease_id}", lease, EXCHANGE_LEASE_DIR)

    # Audit event: lease.issued
    audit = _audit_event("lease.issued", {
        "lease_id": lease_id,
        "scope": scope,
        "ttl": ttl,
        "issued_at": issued_at,
        "requested_by": requested_by,
        "exchange_path": str(lease_path.relative_to(EXCHANGE_LEASE_DIR.parent)),
    })
    _drop_to_exchange("audit_lease_issued", audit, EXCHANGE_AUDIT_DIR)

    # Witness entry (composes with watchdog/witness)
    _log_witness({
        "event": "lease.issued",
        "lease_id": lease_id,
        "scope": scope,
        "ttl": ttl,
        "broker_pubkey_prefix": pub_hex[:16],
    })

    return lease


def revoke_lease(lease_id: str, reason: str = "unspecified") -> dict:
    """Mark a lease as revoked. Appends a signed audit event.

    Note: this does NOT delete the lease — leases persist as evidence.
    Verifier checks lease expiry + audit-log for revocation events on
    the same lease_id. For full revocation the verifier would consult a
    revocation list; TTL expiry is the canonical revocation surface;
    explicit revocation is for compromise response.
    """
    revoked_at = datetime.now(timezone.utc).isoformat()

    # Audit event: lease.revoked
    audit = _audit_event("lease.revoked", {
        "lease_id": lease_id,
        "reason": reason,
        "revoked_at": revoked_at,
    })
    _drop_to_exchange("audit_lease_revoked", audit, EXCHANGE_AUDIT_DIR)

    # Witness entry
    _log_witness({
        "event": "lease.revoked",
        "lease_id": lease_id,
        "reason": reason,
    })

    return audit


def _log_witness(entry: dict) -> None:
    """Append to the witness log."""
    WITNESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    with WITNESS_LOG.open("a") as f:
        f.write(json.dumps(record) + "\n")


# Module-level broker key cache (lazy init)
_broker_sk_cache = None


def _broker_sk() -> ed25519.SigningKey:
    global _broker_sk_cache
    if _broker_sk_cache is None:
        _broker_sk_cache = _load_or_create_broker_key()
    return _broker_sk_cache


# =============================================================================
# Socket server
# =============================================================================

def _handle_request(req: dict) -> dict:
    """Dispatch one broker request."""
    action = req.get("action")
    if action == "issue":
        return {
            "ok": True,
            "lease": issue_root_lease(
                scope=req.get("scope", "/"),
                ttl=req.get("ttl", DEFAULT_TTL_SECONDS),
                requested_by=req.get("requested_by", "anonymous"),
            ),
        }
    elif action == "revoke":
        return {
            "ok": True,
            "event": revoke_lease(
                lease_id=req.get("lease_id", ""),
                reason=req.get("reason", "unspecified"),
            ),
        }
    elif action == "pubkey":
        return {"ok": True, "pubkey": _broker_pubkey_hex(_broker_sk())}
    elif action == "self-test":
        return {"ok": True, "self_test": _self_test()}
    else:
        return {"ok": False, "error": f"unknown-action: {action}"}


def serve_forever() -> None:
    """Run broker as a Unix-socket server."""
    BROKER_SOCK.parent.mkdir(parents=True, exist_ok=True)
    if BROKER_SOCK.exists():
        BROKER_SOCK.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(BROKER_SOCK))
    os.chmod(BROKER_SOCK, 0o660)
    srv.listen(5)

    _log_witness({
        "event": "broker.start",
        "socket": str(BROKER_SOCK),
        "broker_pubkey_prefix": _broker_pubkey_hex(_broker_sk())[:16],
    })

    print(f"lease_broker: listening on {BROKER_SOCK}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 65536:
                    break
            req = json.loads(data.decode())
            resp = _handle_request(req)
            conn.sendall(json.dumps(resp).encode())
        except Exception as e:
            conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode())
        finally:
            conn.close()


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> dict:
    """Broker self-test: issue a lease, verify signature, revoke."""
    results = []

    # Issue a lease
    lease = issue_root_lease("/docs/*", ttl=3600, requested_by="self-test")
    results.append({
        "test": "issue_root_lease",
        "ok": "sig" in lease and "id" in lease,
        "lease_id": lease["id"],
    })

    # Verify the signature
    try:
        pubkey = ed25519.VerifyKey(bytes.fromhex(lease["signer_pubkey"]))
        payload = {
            "id": lease["id"],
            "scope": lease["scope"],
            "ttl": lease["ttl"],
            "issued_at": lease["issued_at"],
            "parent": lease["parent"],
            "restriction": lease["restriction"],
            "chain_hash_at_issuance": lease["chain_hash_at_issuance"],
        }
        pubkey.verify(_canonical_payload(payload), bytes.fromhex(lease["sig"]))
        results.append({"test": "verify_broker_sig", "ok": True})
    except nacl.exceptions.BadSignatureError:
        results.append({"test": "verify_broker_sig", "ok": False})

    # Revoke and check audit event dropped
    audit = revoke_lease(lease["id"], reason="self-test")
    results.append({
        "test": "revoke_emits_audit",
        "ok": audit.get("event_type") == "lease.revoked",
    })

    return {
        "tests": results,
        "passed": sum(1 for t in results if t["ok"]),
        "total": len(results),
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["serve", "self-test", "issue", "revoke", "pubkey"])
    parser.add_argument("--scope", default="/docs/*")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--lease-id", default="")
    parser.add_argument("--reason", default="manual")
    args = parser.parse_args()

    if args.mode == "serve":
        serve_forever()
    elif args.mode == "self-test":
        result = _self_test()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["passed"] == result["total"] else 1)
    elif args.mode == "issue":
        lease = issue_root_lease(args.scope, args.ttl, requested_by="cli")
        print(json.dumps(lease, indent=2))
    elif args.mode == "revoke":
        audit = revoke_lease(args.lease_id, args.reason)
        print(json.dumps(audit, indent=2))
    elif args.mode == "pubkey":
        print(_broker_pubkey_hex(_broker_sk()))
