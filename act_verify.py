#!/usr/bin/env python3
"""
act_verify.py — Attenuated Capability Token (ACT) verifier.

Implements a verifiable delegation primitive where permissions can
only narrow, never expand. A broker signs root leases; holders sign
sub-leases that add restrictions; consumers verify the entire chain.

API contract:
    verify_token(token_chain, requested_action)
        -> {valid: bool, audit_trail: [...], reason: str|None}

Design properties:
    * Ed25519 signatures (PyNaCl) on each lease link.
    * Single-linked-list chains (no trees) — rejects cousin attacks.
    * Chain hash binding (chain_hash_at_issuance) defends against
      replay of stale sub-leases onto a different parent chain.
    * Lazy registration of unknown signers (verify first, then
      register) — matches mTLS-style trust-on-first-use.
    * TTL-based expiry + clock-skew defense on issued_at.
    * 4 adversarial defenses baked in:
        1. Scope-confusion (Lens 8)
        2. Restriction-not-narrowed
        3. Cousin-chain (single-link-list invariant)
        4. Replay-of-stale-restriction (chain_hash_at_issuance)

This is a reference implementation. Drop-in for any system needing
verifiable, narrowing-only delegation.

Authored 2026-09 by Lez (doctrine-and-research).
MIT License.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import nacl.signing as ed25519
import nacl.exceptions


# Trust store — broker is the root authority. Holders register lazily.
# Bootstrap key is the broker's well-known public key (replace with
# your deployment's value).
TRUSTED_SIGNERS = {
    "BOOTSTRAP_BROKER_PUBKEY_PLACEHOLDER": "broker-bootstrap",
}

DEFAULT_TTL_SECONDS = 3600  # 1 hour
MAX_CLOCK_SKEW_SECONDS = 60  # reject issued_at > now + 60s


@dataclass
class Lease:
    """A single link in the attenuation chain.

    Mirrors the primitive contract:
        RootLease:  {id, scope, ttl, sig}
        SubLease:   {parent, scope, restriction, sig}
    """
    id: str
    scope: str  # path prefix, e.g. "/docs/*"
    ttl: int  # seconds
    issued_at: str  # RFC3339
    parent: Optional[str] = None  # id of parent lease, None for root
    restriction: Optional[str] = None  # action allowlist, None for root
    chain_hash_at_issuance: Optional[str] = None  # for replay defense
    signer_pubkey: Optional[str] = None
    sig: Optional[str] = None  # ed25519 sig over canonical payload

    def is_root(self) -> bool:
        return self.parent is None

    def canonical_payload(self) -> bytes:
        """Bytes that get signed. Excludes sig itself + signer_pubkey
        (which is identity, not payload)."""
        payload = {
            "id": self.id,
            "scope": self.scope,
            "ttl": self.ttl,
            "issued_at": self.issued_at,
            "parent": self.parent,
            "restriction": self.restriction,
            "chain_hash_at_issuance": self.chain_hash_at_issuance,
        }
        return json.dumps(payload, sort_keys=True).encode()


@dataclass
class VerifyResult:
    valid: bool
    audit_trail: list = field(default_factory=list)
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "audit_trail": self.audit_trail,
            "reason": self.reason,
        }


def _hash_chain(leases: list) -> str:
    """SHA-256 hash of the chain at this point. Used for replay defense."""
    import hashlib
    h = hashlib.sha256()
    for l in leases:
        h.update(l.canonical_payload())
    return h.hexdigest()


def _scope_subset(child_scope: str, parent_scope: str) -> bool:
    """Check that child_scope is a strict subset of parent_scope.

    Both are path-prefix patterns. '*' is the wildcard.
    """
    parent = parent_scope.rstrip("/") or "/"
    child = child_scope.rstrip("/") or "/"

    if parent.endswith("/*"):
        prefix = parent[:-2]
        if child == prefix or child.startswith(prefix + "/"):
            return True
        return False
    return child == parent or child.startswith(parent + "/")


def _restriction_subset(child_restriction: Optional[str], parent_restriction: Optional[str]) -> bool:
    """Check that child restriction narrows parent.

    Action allowlist semantics: child is a subset of parent if every
    action in child is in parent (or parent has no restriction).
    None means "no restriction" (allow anything).
    """
    if parent_restriction is None:
        return True
    if child_restriction is None:
        return False
    parent_set = set(parent_restriction.split(","))
    child_set = set(child_restriction.split(","))
    return child_set.issubset(parent_set)


def verify_token(token_chain: list, requested_action: str) -> VerifyResult:
    """Verify an Attenuated Capability Token chain.

    Returns VerifyResult with valid flag, audit_trail (all sigs in
    chain order), and reason on failure.

    Rejects:
        * empty chain
        * chain not rooted (no root at index 0)
        * chain link broken (parent id mismatch)
        * future issued_at (clock-skew attack)
        * expired lease (TTL exceeded)
        * missing signature
        * bad signature on unknown signer (rejected before lazy-register)
        * bad signature on known signer
        * scope expansion at any layer
        * restriction not narrowed at any layer
        * chain_hash_at_issuance mismatch (replay attack)
        * action not allowed by leaf restriction
    """
    if not token_chain:
        return VerifyResult(valid=False, reason="empty-chain")

    if not isinstance(token_chain, list):
        return VerifyResult(valid=False, reason="chain-not-list")

    # Chain must be a single linked list, not a tree
    for i, lease in enumerate(token_chain):
        if i == 0:
            if not lease.is_root():
                return VerifyResult(valid=False, reason="chain-not-rooted")
        else:
            if lease.parent != token_chain[i - 1].id:
                return VerifyResult(valid=False, reason=f"chain-link-broken-at-{i}")

    # Walk and verify each link
    audit_trail = []
    for i, lease in enumerate(token_chain):
        # Clock-skew defense
        try:
            issued_dt = datetime.fromisoformat(lease.issued_at)
        except (ValueError, TypeError):
            return VerifyResult(valid=False, reason=f"invalid-issued_at-at-{i}")
        now = datetime.now(timezone.utc)
        if issued_dt > now.replace(tzinfo=timezone.utc) + _allowed_skew():
            return VerifyResult(
                valid=False,
                audit_trail=audit_trail,
                reason=f"issued_at-future-at-{i}",
            )

        # TTL check
        elapsed = (now - issued_dt.replace(tzinfo=issued_dt.tzinfo or timezone.utc)).total_seconds()
        if elapsed > lease.ttl:
            return VerifyResult(
                valid=False,
                audit_trail=audit_trail,
                reason=f"lease-expired-at-{i}",
            )

        # Verify signature
        if not lease.sig or not lease.signer_pubkey:
            return VerifyResult(
                valid=False,
                audit_trail=audit_trail,
                reason=f"missing-sig-at-{i}",
            )

        # Lazy-register unknown signers (verify first, then register)
        if lease.signer_pubkey not in TRUSTED_SIGNERS:
            try:
                pubkey = ed25519.VerifyKey(bytes.fromhex(lease.signer_pubkey))
                pubkey.verify(lease.canonical_payload(), bytes.fromhex(lease.sig))
            except nacl.exceptions.BadSignatureError:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"bad-sig-unknown-signer-at-{i}",
                )
            except Exception as e:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"verify-error-at-{i}:{type(e).__name__}",
                )
            TRUSTED_SIGNERS[lease.signer_pubkey] = f"holder-{lease.id} (lazy)"
        else:
            try:
                pubkey = ed25519.VerifyKey(bytes.fromhex(lease.signer_pubkey))
                pubkey.verify(lease.canonical_payload(), bytes.fromhex(lease.sig))
            except nacl.exceptions.BadSignatureError:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"bad-sig-at-{i}",
                )
            except Exception as e:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"verify-error-at-{i}:{type(e).__name__}",
                )

        # Scope-confusion defense
        if not lease.is_root():
            parent = token_chain[i - 1]
            if not _scope_subset(lease.scope, parent.scope):
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"scope-expansion-at-{i}",
                )

        # Restriction narrowing
        if not lease.is_root():
            parent = token_chain[i - 1]
            if not _restriction_subset(lease.restriction, parent.restriction):
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"restriction-not-narrowed-at-{i}",
                )

        # Replay defense: chain_hash_at_issuance binds leaf to chain above parent
        if not lease.is_root():
            if lease.chain_hash_at_issuance is None:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"missing-chain-hash-at-{i}",
                )
            parent_chain = token_chain[:i]
            expected_hash = _hash_chain(parent_chain)
            if lease.chain_hash_at_issuance != expected_hash:
                return VerifyResult(
                    valid=False,
                    audit_trail=audit_trail,
                    reason=f"chain-hash-mismatch-at-{i}",
                )

        audit_trail.append({
            "lease_id": lease.id,
            "signer_pubkey_prefix": lease.signer_pubkey[:16],
            "sig": lease.sig,
            "scope": lease.scope,
            "restriction": lease.restriction,
        })

    # Final check: requested_action must be within the leaf's restriction
    leaf = token_chain[-1]
    if not _action_allowed(requested_action, leaf.restriction):
        return VerifyResult(
            valid=False,
            audit_trail=audit_trail,
            reason="action-not-allowed-by-leaf",
        )

    return VerifyResult(valid=True, audit_trail=audit_trail, reason=None)


def _allowed_skew():
    from datetime import timedelta
    return timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)


def _action_allowed(action: str, restriction: Optional[str]) -> bool:
    if restriction is None:
        return True
    allowed = set(restriction.split(","))
    return action in allowed


# =============================================================================
# Test battery
# =============================================================================

def _make_root(sk: ed25519.SigningKey, scope: str, ttl: int = DEFAULT_TTL_SECONDS,
               lease_id: Optional[str] = None) -> Lease:
    """Broker issues a root lease."""
    import secrets
    issued_at = datetime.now(timezone.utc).isoformat()
    lease = Lease(
        id=lease_id or f"root-{secrets.token_hex(4)}",
        scope=scope,
        ttl=ttl,
        issued_at=issued_at,
        signer_pubkey=bytes(sk.verify_key).hex(),
    )
    lease.sig = sk.sign(lease.canonical_payload()).signature.hex()
    return lease


def _make_sublease(parent: Lease, sk: ed25519.SigningKey, scope: str,
                   restriction: str, chain_above: Optional[list] = None) -> Lease:
    """Holder attenuates a parent lease.

    chain_above: list of leases strictly ABOVE the parent. If parent
    is the root, pass []. The leaf's chain_hash_at_issuance binds it
    to the FULL chain (chain_above + [parent]).
    """
    import secrets
    issued_at = datetime.now(timezone.utc).isoformat()
    full_chain = (chain_above or []) + [parent]
    chain_hash = _hash_chain(full_chain)
    lease = Lease(
        id=f"sub-{parent.id}-{secrets.token_hex(2)}",
        scope=scope,
        ttl=parent.ttl,
        issued_at=issued_at,
        parent=parent.id,
        restriction=restriction,
        chain_hash_at_issuance=chain_hash,
        signer_pubkey=bytes(sk.verify_key).hex(),
    )
    lease.sig = sk.sign(lease.canonical_payload()).signature.hex()
    return lease


def _self_test():
    """Run a battery of test cases; print PASS/FAIL for each."""
    broker = ed25519.SigningKey.generate()
    broker_pub = bytes(broker.verify_key).hex()
    TRUSTED_SIGNERS[broker_pub] = "broker-self-test"

    holder = ed25519.SigningKey.generate()

    results = []

    root = _make_root(broker, "/docs/*")
    sub = _make_sublease(root, holder, "/docs/care-guide", "read,list")
    r = verify_token([root, sub], "read")
    results.append(("valid-chain-action-allowed", r.valid and r.reason is None))

    r = verify_token([root, sub], "write")
    results.append(("action-not-allowed", not r.valid and "action-not-allowed" in r.reason))

    evil_sub = _make_sublease(root, holder, "/etc/*", "read")
    r = verify_token([root, evil_sub], "read")
    results.append(("scope-expansion-rejected", not r.valid and "scope-expansion" in r.reason))

    restricted_root = _make_root(broker, "/docs/*")
    restricted_root.restriction = "read"
    restricted_root.sig = broker.sign(restricted_root.canonical_payload()).signature.hex()
    expanded_sub = _make_sublease(restricted_root, holder, "/docs/care-guide",
                                  "read,write,delete")
    r = verify_token([restricted_root, expanded_sub], "read")
    results.append(("restriction-not-narrowed-rejected",
                    not r.valid and "restriction-not-narrowed" in r.reason))

    other_root = _make_root(broker, "/etc/*")
    broken = _make_sublease(other_root, holder, "/etc/passwd", "read")
    r = verify_token([root, broken], "read")
    results.append(("chain-link-broken-rejected",
                    not r.valid and "chain-link-broken" in r.reason))

    tampered = _make_sublease(root, holder, "/docs/care-guide", "read")
    tampered.scope = "/etc/shadow"
    r = verify_token([root, tampered], "read")
    results.append(("tampered-scope-bad-sig",
                    not r.valid and "bad-sig" in r.reason))

    fresh_root = _make_root(broker, "/docs/*")
    forged_sub = _make_sublease(fresh_root, holder, "/docs/care-guide", "read")
    stale_hash = _hash_chain([root])
    forged_sub.chain_hash_at_issuance = stale_hash
    forged_sub.sig = holder.sign(forged_sub.canonical_payload()).signature.hex()
    r = verify_token([fresh_root, forged_sub], "read")
    results.append(("chain-hash-mismatch-rejected",
                    not r.valid and "chain-hash-mismatch" in r.reason))

    r = verify_token([], "read")
    results.append(("empty-chain-rejected",
                    not r.valid and r.reason == "empty-chain"))

    sub_only = _make_sublease(root, holder, "/docs/care-guide", "read")
    r = verify_token([sub_only], "read")
    results.append(("non-rooted-chain-rejected",
                    not r.valid and r.reason == "chain-not-rooted"))

    expired_root = _make_root(broker, "/docs/*", ttl=1)
    import time
    time.sleep(2)
    r = verify_token([expired_root], "read")
    results.append(("expired-lease-rejected",
                    not r.valid and "expired" in r.reason))

    future_root = Lease(
        id="root-future",
        scope="/docs/*",
        ttl=DEFAULT_TTL_SECONDS,
        issued_at=datetime.now(timezone.utc).replace(year=2030).isoformat(),
        signer_pubkey=broker_pub,
    )
    future_root.sig = broker.sign(future_root.canonical_payload()).signature.hex()
    r = verify_token([future_root], "read")
    results.append(("future-issued_at-rejected",
                    not r.valid and "issued_at-future" in r.reason))

    chain = [_make_root(broker, "/data/*", ttl=3600)]
    nested_scope = "/data/*"
    for i in range(4):
        parent = chain[-1]
        h = ed25519.SigningKey.generate()
        nested_scope = nested_scope.rstrip("/*") + f"/layer{i}/*"
        chain_above = list(chain[:-1])
        chain.append(_make_sublease(parent, h, nested_scope, "read",
                                    chain_above=chain_above))
    r = verify_token(chain, "read")
    results.append(("deep-chain-valid", r.valid and len(r.audit_trail) == 5))

    print("=" * 60)
    print("ACT verifier self-test")
    print("=" * 60)
    passed = 0
    for name, ok in results:
        marker = "[PASS]" if ok else "[FAIL]"
        print(f"  {marker} {name}")
        if ok:
            passed += 1
    print("=" * 60)
    print(f"  {passed}/{len(results)} tests passed")
    return passed == len(results)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "self-test":
        sys.exit(0 if _self_test() else 1)
    else:
        print("Reference implementation of an Attenuated Capability Token verifier.")
        print("Run `python3 act_verify.py self-test` to execute the test battery.")
        print()
        print("Public API:")
        print("  verify_token(token_chain, requested_action) -> VerifyResult")
        print("  Lease dataclass with is_root(), canonical_payload()")
        print("  TRUSTED_SIGNERS registry (lazy-register on first verify)")
