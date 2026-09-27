#!/usr/bin/env python3
"""
act_integration_test.py — End-to-end test of the ACT three-component chain.

Tests:
  1. Broker issues root lease, drops to lease dir
  2. Audit collector picks up the broker's lease.issued event,
     verifies the broker's signature, appends to local audit chain
  3. Verifier accepts the issued lease when presented
  4. Holder attenuates the root lease (client-side)
  5. Verifier accepts the attenuated sub-lease
  6. Verifier rejects tampered sub-lease
  7. Broker revokes the lease
  8. Audit collector picks up the revocation event
  9. Verifier still accepts the lease (TTL is canonical revocation
     surface; explicit revoke is forensic record, not deny-list)

Authored 2026-09.
MIT License.
"""

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import nacl.signing as ed25519

sys.path.insert(0, str(Path(__file__).parent))
import lease_broker
import lease_audit_collector as collector
from act_verify import verify_token, Lease, TRUSTED_SIGNERS as VERIFIER_TRUST, _hash_chain


def _run() -> dict:
    results = []

    with tempfile.TemporaryDirectory(prefix="act-integration-") as tmp:
        tmp_path = Path(tmp)
        bus_dir = tmp_path / "audit-bus"
        leases_dir = tmp_path / "leases"
        bus_dir.mkdir()
        leases_dir.mkdir()

        # Setup: consumer signing key + broker key
        consumer_sk = ed25519.SigningKey.generate()
        consumer_pub = bytes(consumer_sk.verify_key).hex()

        # Patch broker paths to use the temp dir
        lease_broker.BROKER_KEY_FILE = tmp_path / "broker.key"
        lease_broker.EXCHANGE_LEASE_DIR = leases_dir
        lease_broker.EXCHANGE_AUDIT_DIR = bus_dir
        lease_broker.WITNESS_LOG = tmp_path / "witness.log"
        lease_broker._broker_sk_cache = None  # reset module cache

        # Patch collector paths
        collector.AUDIT_BUS_DIR = bus_dir
        collector.CONSUMER_AUDIT_LOG = tmp_path / "audit.log"
        collector.CONSUMER_AUDIT_CHAIN_HEAD = tmp_path / "chain-head"
        collector.CONSUMER_SIGNING_KEY_FILE = tmp_path / "consumer.key"
        collector.COLLECTOR_LOG = tmp_path / "collector.log"
        collector.CONSUMER_SIGNING_KEY_FILE.write_bytes(bytes(consumer_sk))
        collector.KNOWN_BROKER_KEYS.clear()

        # Patch verifier's TRUSTED_SIGNERS so it knows about our broker
        broker = lease_broker._load_or_create_broker_key()
        broker_pub = bytes(broker.verify_key).hex()
        VERIFIER_TRUST[broker_pub] = "broker-integration-test"

        # Step 1: Broker issues a root lease
        lease = lease_broker.issue_root_lease(
            "/docs/*", ttl=3600, requested_by="integration-test"
        )
        assert lease["id"].startswith("root-")
        assert lease["scope"] == "/docs/*"
        assert "sig" in lease
        assert lease["signer_pubkey"] == broker_pub
        results.append({"step": "broker.issue_root_lease", "ok": True, "lease_id": lease["id"]})

        # Verify the lease was dropped
        lease_files = list(leases_dir.glob("lease_*.json"))
        assert len(lease_files) == 1, f"Expected 1 lease file, got {len(lease_files)}"
        results.append({"step": "broker.drops_lease", "ok": True})

        # Step 2: Audit collector picks up the issuance event
        audit_files = list(bus_dir.glob("audit_lease_issued_*.json"))
        assert len(audit_files) == 1, f"Expected 1 audit file, got {len(audit_files)}"

        processed = set()
        collector.process_one(audit_files[0], processed)

        # Verify the audit chain was extended
        assert collector.CONSUMER_AUDIT_LOG.exists()
        consumer_entries = collector.CONSUMER_AUDIT_LOG.read_text().strip().split("\n")
        assert len(consumer_entries) == 1, f"Expected 1 entry, got {len(consumer_entries)}"
        consumer_entry = json.loads(consumer_entries[0])
        assert consumer_entry["payload"]["event"] == "lease.issued"
        assert consumer_entry["payload"]["lease_id"] == lease["id"]
        assert consumer_entry["payload"]["broker_pubkey"] == broker_pub
        results.append({"step": "collector.appends_to_chain", "ok": True})

        # Step 3: Verifier accepts the broker's lease
        parsed_root = Lease(
            id=lease["id"],
            scope=lease["scope"],
            ttl=lease["ttl"],
            issued_at=lease["issued_at"],
            signer_pubkey=lease["signer_pubkey"],
            sig=lease["sig"],
        )
        r = verify_token([parsed_root], "read")
        assert r.valid, f"Verifier rejected broker lease: {r.reason}"
        results.append({"step": "verifier.accepts_broker_lease", "ok": True})

        # Step 4: Holder attenuates (client-side sub-lease)
        holder = ed25519.SigningKey.generate()
        sub = Lease(
            id=f"sub-{lease['id']}-1",
            scope="/docs/care-guide",
            ttl=lease["ttl"],
            issued_at=datetime.now(timezone.utc).isoformat(),
            parent=lease["id"],
            restriction="read,list",
            chain_hash_at_issuance=_hash_chain([parsed_root]),
            signer_pubkey=bytes(holder.verify_key).hex(),
        )
        sub.sig = holder.sign(sub.canonical_payload()).signature.hex()
        results.append({"step": "holder.attenuates_sublease", "ok": True})

        # Step 5: Verifier accepts the attenuated chain
        r = verify_token([parsed_root, sub], "read")
        assert r.valid, f"Verifier rejected sub-lease: {r.reason}"
        assert len(r.audit_trail) == 2
        results.append({"step": "verifier.accepts_attenuated_chain", "ok": True})

        # Step 6: Verifier rejects tampered sub-lease
        tampered = Lease(
            id=sub.id,
            scope="/etc/shadow",  # scope expansion
            ttl=sub.ttl,
            issued_at=sub.issued_at,
            parent=sub.parent,
            restriction=sub.restriction,
            chain_hash_at_issuance=sub.chain_hash_at_issuance,
            signer_pubkey=sub.signer_pubkey,
        )
        tampered.sig = holder.sign(tampered.canonical_payload()).signature.hex()
        r = verify_token([parsed_root, tampered], "read")
        assert not r.valid
        assert "scope-expansion" in r.reason
        results.append({"step": "verifier.rejects_scope_expansion", "ok": True})

        # Step 7: Broker revokes
        revoke_event = lease_broker.revoke_lease(lease["id"], reason="integration-test-revoke")
        assert revoke_event["event_type"] == "lease.revoked"
        results.append({"step": "broker.revoke_emits_event", "ok": True})

        # Step 8: Audit collector picks up revocation
        revoke_audit_files = [f for f in bus_dir.glob("audit_lease_revoked_*.json")]
        assert len(revoke_audit_files) == 1
        collector.process_one(revoke_audit_files[0], processed)
        consumer_entries_after = collector.CONSUMER_AUDIT_LOG.read_text().strip().split("\n")
        assert len(consumer_entries_after) == 2, \
            f"Expected 2 entries, got {len(consumer_entries_after)}"
        assert json.loads(consumer_entries_after[1])["payload"]["event"] == "lease.revoked"
        results.append({"step": "collector.appends_revoke", "ok": True})

        # Step 9: Verifier still accepts the lease (TTL is canonical;
        # explicit revoke is forensic record, not deny-list)
        r = verify_token([parsed_root], "read")
        assert r.valid, f"Verifier rejected after revoke (TTL still valid): {r.reason}"
        results.append({"step": "verifier.lease_still_valid_until_ttl",
                        "ok": True,
                        "honest_note": "explicit revoke is forensic, not deny-list"})

        # Step 10: Idempotency — reprocessing same file is a no-op
        first_count = len(collector.CONSUMER_AUDIT_LOG.read_text().strip().split("\n"))
        collector.process_one(audit_files[0], processed)
        second_count = len(collector.CONSUMER_AUDIT_LOG.read_text().strip().split("\n"))
        assert first_count == second_count
        results.append({"step": "collector.idempotent", "ok": True})

    return {
        "tests": results,
        "passed": sum(1 for t in results if t["ok"]),
        "total": len(results),
    }


if __name__ == "__main__":
    result = _run()
    print("=" * 60)
    print("ACT Integration Test — broker + collector + verifier")
    print("=" * 60)
    for t in result["tests"]:
        marker = "PASS" if t["ok"] else "FAIL"
        note = f"  ({t.get('honest_note', '')})" if t.get('honest_note') else ""
        print(f"  [{marker}] {t['step']}{note}")
    print("=" * 60)
    print(f"  {result['passed']}/{result['total']} integration steps passed")
    sys.exit(0 if result["passed"] == result["total"] else 1)
