#!/usr/bin/env python3
"""
act_verify.py — Attenuated Capability Token (ACT) verifier.

Implements a verifiable delegation primitive where permissions can
only narrow, never expand. A broker signs root leases; holders sign
sub-leases that add restrictions; consumers verify the entire chain.

API contract:
    verify_token(token_chain, requested_action, witness_receipts=None)
        -> {valid: bool, audit_trail: [...], reason: str|None,
            witness_check: {...}}

    witness_check keys: provided (bool), ok (bool), reason (str|None),
    last_seq (int|None), last_chain_head (str|None),
    consumer_chain_head (str|None), freshness (str|None),
    staleness_seconds (int|None), receipts_checked (int)

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
    * Direction 7 + 6 composition (Cycle 7.66 C):
        witness_receipts parameter accepts D6 heartbeat-witnessed
        entries to anchor consumer's chain head to colony-witnessed
        chain head. Opt-in for backwards compatibility.

This is a reference implementation. Drop-in for any system needing
verifiable, narrowing-only delegation.

Authored 2026-09 by Lez (doctrine-and-research).
MIT License.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
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

# Witness receipt defaults (Cycle 7.66 C — Direction 7 + 6 composition)
DEFAULT_WITNESS_STALENESS_SECONDS = 24 * 3600  # 24h default
WITNESS_BOOTSTRAP_PUBKEY_PLACEHOLDER = "WITNESS_BOOTSTRAP_PUBKEY_PLACEHOLDER"


@dataclass
class WitnessReceipt:
    """A single D6 heartbeat-witnessed entry.

    Cycle 7.66 C contract:
        seq:           monotonic sequence (int, ascending)
        chain_head:    audit-chain head mirrored by the witness
        source_ts:     ISO8601 timestamp of the source heartbeat (str)
        signer_pubkey: witness's ed25519 pubkey hex (str)
        sig:           ed25519 sig over canonical payload (str)

    The verifier DOES NOT trust signer_pubkey from the receipt alone;
    it must be looked up in COLONY_KEYS (passed as colony_keys).
    Receipts missing required fields are rejected.
    """
    seq: int
    chain_head: str
    source_ts: str
    signer_pubkey: str
    sig: str

    def canonical_payload(self) -> bytes:
        """Bytes that get signed. Excludes sig itself + signer_pubkey
        (which is identity, not payload)."""
        payload = {
            "seq": self.seq,
            "chain_head": self.chain_head,
            "source_ts": self.source_ts,
        }
        return json.dumps(payload, sort_keys=True).encode()


def _empty_witness_check() -> dict:
    """Witness-check stub when receipts are not provided."""
    return {
        "provided": False,
        "ok": True,
        "reason": None,
        "last_seq": None,
        "last_chain_head": None,
        "consumer_chain_head": None,
        "freshness": None,
        "staleness_seconds": None,
        "receipts_checked": 0,
    }


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
    witness_check: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "audit_trail": self.audit_trail,
            "reason": self.reason,
            "witness_check": self.witness_check,
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


def verify_token(
    token_chain: list,
    requested_action: str,
    *,
    witness_receipts: Optional[list] = None,
    colony_keys: Optional[dict] = None,
    consumer_chain_head: Optional[str] = None,
    staleness_seconds: int = DEFAULT_WITNESS_STALENESS_SECONDS,
) -> VerifyResult:
    """Verify an Attenuated Capability Token chain.

    Returns VerifyResult with valid flag, audit_trail (all sigs in
    chain order), witness_check (Direction 7+6 composition surface),
    and reason on failure.

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
        * (when witness_receipts provided) receipt sig fail
        * (when witness_receipts provided) receipt seq gap
        * (when witness_receipts provided) consumer chain head diverges
          from witnessed chain head
        * (when witness_receipts provided) all receipts stale beyond
          staleness_seconds (configurable; defaults to fail-closed at 24h)

    Direction 7 + 6 composition (Cycle 7.66 C):
        When `witness_receipts` is provided (non-empty list), the
        verifier anchors the consumer's claimed chain head to the
        colony-witnessed chain head. witness_receipts is opt-in;
        callers without witness access continue to work unchanged.

        `colony_keys` MUST be provided when witness_receipts is
        non-empty. colony_keys maps witness_pubkey_hex -> label.
        Receipts from unknown witness keys are rejected.

        `consumer_chain_head` is the consumer's local view of the
        audit chain head. Compared against the most-recent receipt's
        chain_head. Mismatch = `witness.chain-head-divergence`.
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

    # Direction 7 + 6 composition (Cycle 7.66 C): if witness_receipts
    # were provided, anchor the consumer's chain head to the witnessed
    # chain head. Opt-in: empty/None = backwards-compatible.
    witness_check = _empty_witness_check()
    if witness_receipts:
        if colony_keys is None:
            return VerifyResult(
                valid=False,
                audit_trail=audit_trail,
                witness_check=witness_check,
                reason="witness.colony-keys-missing",
            )
        witness_check = _verify_witness_receipts(
            witness_receipts,
            colony_keys,
            consumer_chain_head=consumer_chain_head,
            staleness_seconds=staleness_seconds,
        )
        if not witness_check["ok"]:
            return VerifyResult(
                valid=False,
                audit_trail=audit_trail,
                witness_check=witness_check,
                reason=witness_check["reason"],
            )

    return VerifyResult(
        valid=True,
        audit_trail=audit_trail,
        witness_check=witness_check,
        reason=None,
    )


def _allowed_skew():
    from datetime import timedelta
    return timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)


def _action_allowed(action: str, restriction: Optional[str]) -> bool:
    if restriction is None:
        return True
    allowed = set(restriction.split(","))
    return action in allowed


def _verify_witness_receipts(
    receipts: list,
    colony_keys: dict,
    consumer_chain_head: Optional[str],
    staleness_seconds: int,
) -> dict:
    """Verify witness receipts (Direction 7 + 6 composition, Cycle 7.66 C).

    Performs 4 checks:
        1. Verify each receipt signature against the witness pubkey
           registered in colony_keys. Unknown witness = reject.
        2. Verify receipt chain integrity (strictly ascending seq;
           gaps fail-closed).
        3. Anchor consumer's claimed chain head to the most-recent
           witnessed chain head. Mismatch = reject.
        4. Anchor freshness: most-recent receipt must be within
           staleness_seconds. Stale = reject.

    Returns a dict:
        {
          "provided": True,
          "ok": bool,
          "reason": str|None,
          "last_seq": int|None,
          "last_chain_head": str|None,
          "consumer_chain_head": str|None,
          "freshness": "fresh"|"stale"|None,
          "staleness_seconds": int,
          "receipts_checked": int,
        }
    """
    base_check = _empty_witness_check()
    base_check["provided"] = True
    base_check["staleness_seconds"] = staleness_seconds
    base_check["consumer_chain_head"] = consumer_chain_head

    if not isinstance(receipts, list) or len(receipts) == 0:
        base_check["ok"] = False
        base_check["reason"] = "witness.empty-receipts"
        return base_check

    # Sort receipts by seq ascending (deterministic order).
    sorted_receipts = sorted(receipts, key=lambda r: int(r.seq))

    last_seq = None
    last_chain_head = None
    last_source_ts = None
    for i, receipt in enumerate(sorted_receipts):
        # 1. Witness-key membership (this is the colony-side check;
        #    receipt's own sig verification is step 2).
        if receipt.signer_pubkey not in colony_keys:
            base_check["ok"] = False
            base_check["reason"] = f"witness.unknown-signer-at-{i}"
            base_check["receipts_checked"] = i
            return base_check

        # 2. Receipt signature.
        try:
            pubkey = ed25519.VerifyKey(bytes.fromhex(receipt.signer_pubkey))
            pubkey.verify(receipt.canonical_payload(), bytes.fromhex(receipt.sig))
        except nacl.exceptions.BadSignatureError:
            base_check["ok"] = False
            base_check["reason"] = f"witness.sig-fail-at-{i}"
            base_check["receipts_checked"] = i
            return base_check
        except Exception as e:
            base_check["ok"] = False
            base_check["reason"] = f"witness.verify-error-at-{i}:{type(e).__name__}"
            base_check["receipts_checked"] = i
            return base_check

        # 3. Receipt chain integrity (strictly ascending seq, no gaps).
        if last_seq is not None:
            if receipt.seq <= last_seq:
                base_check["ok"] = False
                base_check["reason"] = f"witness.seq-not-ascending-at-{i}"
                base_check["receipts_checked"] = i
                return base_check
            if receipt.seq != last_seq + 1:
                # seq gap: fail-closed.
                base_check["ok"] = False
                base_check["reason"] = f"witness.seq-gap-at-{i}"
                base_check["receipts_checked"] = i
                return base_check

        last_seq = receipt.seq
        last_chain_head = receipt.chain_head
        last_source_ts = receipt.source_ts

    base_check["receipts_checked"] = len(sorted_receipts)
    base_check["last_seq"] = last_seq
    base_check["last_chain_head"] = last_chain_head

    # 4. Chain-head divergence: consumer's claimed head vs witnessed head.
    if consumer_chain_head is not None:
        if consumer_chain_head != last_chain_head:
            base_check["ok"] = False
            base_check["reason"] = "witness.chain-head-divergence"
            return base_check

    # 5. Freshness: most-recent receipt must be within staleness window.
    try:
        source_dt = datetime.fromisoformat(last_source_ts)
    except (ValueError, TypeError):
        base_check["ok"] = False
        base_check["reason"] = "witness.invalid-source-ts"
        return base_check
    now = datetime.now(timezone.utc)
    age = (now - source_dt.replace(tzinfo=source_dt.tzinfo or timezone.utc)).total_seconds()
    if age > staleness_seconds:
        base_check["ok"] = False
        base_check["reason"] = "witness.stale"
        base_check["freshness"] = "stale"
        return base_check
    base_check["freshness"] = "fresh"

    base_check["ok"] = True
    return base_check


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

    # ===== Cycle 7.66 C — Direction 7 + 6 composition tests =====
    # Witness-receipt tests share a clean chain + a fresh witness keypair.
    witness_sk = ed25519.SigningKey.generate()
    witness_pub = bytes(witness_sk.verify_key).hex()
    colony_keys = {"broker-self-test": broker_pub, witness_pub: "D4-witness-self-test"}
    consumer_root = _make_root(broker, "/docs/*")
    consumer_sub = _make_sublease(consumer_root, holder, "/docs/care-guide", "read,list")
    consumer_chain = [consumer_root, consumer_sub]
    # Hash the consumer chain to use as a believable chain_head for matching.
    consumer_head = _hash_chain(consumer_chain)

    def _make_receipt(seq: int, chain_head: str, source_ts: str,
                      sk: ed25519.SigningKey = witness_sk) -> WitnessReceipt:
        r = WitnessReceipt(
            seq=seq,
            chain_head=chain_head,
            source_ts=source_ts,
            signer_pubkey=bytes(sk.verify_key).hex(),
            sig="",  # placeholder; signed below
        )
        r.sig = sk.sign(r.canonical_payload()).signature.hex()
        return r

    fresh_ts = datetime.now(timezone.utc).isoformat()

    # Test 1: valid receipt set with matching chain head — accepted.
    receipts_ok = [_make_receipt(1, consumer_head, fresh_ts),
                   _make_receipt(2, consumer_head, fresh_ts),
                   _make_receipt(3, consumer_head, fresh_ts)]
    r = verify_token(
        consumer_chain,
        "read",
        witness_receipts=receipts_ok,
        colony_keys=colony_keys,
        consumer_chain_head=consumer_head,
    )
    results.append((
        "witness-receipts-accepted",
        r.valid and r.reason is None
        and r.witness_check.get("ok") is True
        and r.witness_check.get("receipts_checked") == 3
        and r.witness_check.get("last_seq") == 3
        and r.witness_check.get("freshness") == "fresh",
    ))

    # Test 2: receipt with bad sig — rejected.
    receipts_bad_sig = [_make_receipt(1, consumer_head, fresh_ts)]
    receipts_bad_sig[0].sig = "00" * 64  # invalid sig
    r = verify_token(
        consumer_chain,
        "read",
        witness_receipts=receipts_bad_sig,
        colony_keys=colony_keys,
        consumer_chain_head=consumer_head,
    )
    results.append((
        "witness-receipt-sig-fail-rejected",
        not r.valid and "witness.sig-fail" in (r.reason or ""),
    ))

    # Test 3: chain-head divergence — consumer claims stale head, witness
    # has newer head. Rejected (defense against forged/subverted consumer).
    receipts_newer_head = [_make_receipt(1, "deadbeef" * 8, fresh_ts)]
    r = verify_token(
        consumer_chain,
        "read",
        witness_receipts=receipts_newer_head,
        colony_keys=colony_keys,
        consumer_chain_head=consumer_head,
    )
    results.append((
        "witness-chain-head-divergence-rejected",
        not r.valid and r.reason == "witness.chain-head-divergence",
    ))

    # Test 4: seq gap — receipts with seq 1, 3 (skip 2). Rejected.
    receipts_with_gap = [_make_receipt(1, consumer_head, fresh_ts),
                         _make_receipt(3, consumer_head, fresh_ts)]
    r = verify_token(
        consumer_chain,
        "read",
        witness_receipts=receipts_with_gap,
        colony_keys=colony_keys,
        consumer_chain_head=consumer_head,
    )
    results.append((
        "witness-seq-gap-rejected",
        not r.valid and "witness.seq-gap" in (r.reason or ""),
    ))

    # Backwards-compat sanity check: no witness_receipts → opt-in path,
    # must succeed as before.
    r = verify_token(consumer_chain, "read")
    results.append((
        "witness-opt-in-backwards-compatible",
        r.valid and r.witness_check.get("provided") is False,
    ))

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
        print("  verify_token(token_chain, requested_action, witness_receipts=None,")
        print("               colony_keys=None, consumer_chain_head=None,")
        print("               staleness_seconds=86400) -> VerifyResult")
        print("  Lease dataclass with is_root(), canonical_payload()")
        print("  WitnessReceipt dataclass with canonical_payload()")
        print("  TRUSTED_SIGNERS registry (lazy-register on first verify)")
        print()
        print("Cycle 7.66 C: witness_receipts opt-in. When provided, the verifier")
        print("anchors the consumer's chain head to the colony-witnessed chain")
