# ACT — Attenuated Capability Tokens

A reference implementation of a verifiable delegation primitive where
permissions can **only narrow, never expand**.

## What is this?

ACT is a delegation pattern designed for systems where one party
issues a capability (a "lease") and another party needs to hand off
sub-pieces of that capability to additional parties — without
giving up more than they received.

The classic example: a CI runner is granted access to deploy a
specific service. A user runs a job that needs to write to a subset
of paths. The user shouldn't be able to grant itself access to
unrelated paths just because the CI runner trusted them.

ACT solves this with:

- **Root leases** — issued by a trusted broker, signed with its
  Ed25519 key, scoped to a path prefix, time-limited.
- **Sub-leases** — holders sign narrower leases (smaller scope,
  smaller action set) chained to a parent. Each sub-lease
  carries the hash of the chain above its parent so it can't be
  replayed onto a different chain.
- **Verification** — a single function `verify_token(chain,
  action)` checks every link's signature, scope narrowing,
  restriction narrowing, chain binding, expiry, and clock-skew
  defense. Returns `valid: bool` plus an `audit_trail` of every
  signature on the chain.

## Repository layout

```
act_verify.py              Verifier + 12-test self-test battery
lease_broker.py            Root-lease broker (Unix socket + drop)
lease_audit_collector.py   Audit-Chain composition for audit events
act_integration_test.py    11-step end-to-end test
LICENSE                    MIT
```

## Quickstart

### Install

```bash
pip install pynacl
```

### Run the verifier's test battery

```bash
python3 act_verify.py self-test
```

Expected: 12/12 tests pass.

### Run the broker's self-test

```bash
python3 lease_broker.py self-test
```

Expected: 3/3 tests pass. The test issues a lease, verifies the
broker's signature, and emits a revoke event.

### Run the collector's self-test

```bash
python3 lease_audit_collector.py self-test
```

Expected: 3/3 tests pass.

### Run the end-to-end integration test

```bash
python3 act_integration_test.py
```

Expected: 11/11 integration steps pass.

## Using the verifier in your own code

```python
from act_verify import verify_token, Lease

# Build a chain (typically loaded from JSON)
chain = [root_lease, sub_lease_1, sub_lease_2]

result = verify_token(chain, requested_action="read")
if result.valid:
    # every link in result.audit_trail is signed by a known
    # signer; the requested action is allowed by the leaf
    do_thing()
else:
    # result.reason is one of: scope-expansion,
    # restriction-not-narrowed, chain-link-broken, etc.
    reject(reason=result.reason)
```

## Issuing leases with the broker

```bash
# Start the broker
python3 lease_broker.py serve

# In another shell, talk to it
python3 -c "
import socket, json
req = json.dumps({'action': 'issue', 'scope': '/api/v1/*', 'ttl': 3600})
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/tmp/act-leases/broker.sock')
sock.sendall(req.encode())
print(sock.recv(65536).decode())
"
```

## How it defends

ACT's verifier rejects:

| Attack | Defense |
|---|---|
| Scope expansion (child claims wider scope than parent) | `_scope_subset()` check on every non-root link |
| Restriction expansion (child claims broader action set) | `_restriction_subset()` check on every non-root link |
| Cousin chain (mixing two chains to make a new one) | Single-linked-list invariant: `lease.parent == prev_lease.id` |
| Replay of stale sub-lease on a different parent chain | `chain_hash_at_issuance` binds leaf to full chain |
| Future-issued_at (clock-skew attack) | Reject if `issued_at > now + 60s` |
| Expired lease | Reject if `now - issued_at > ttl` |
| Forged signature | PyNaCl Ed25519 verify before lazy-register |
| Tampered payload after signing | Signature fails verification |

## Configuration

All paths are read from environment variables. Defaults live under
`/tmp/act-leases/` so a self-test never accidentally writes to your
working directory or anywhere system-owned.

```bash
export BROKER_SOCK=/tmp/act-leases/broker.sock
export EXCHANGE_LEASE_DIR=/tmp/act-leases/leases
export EXCHANGE_AUDIT_DIR=/tmp/act-leases/audit-bus
export BROKER_KEY_FILE=/tmp/act-leases/broker-signing.key
export AUDIT_BUS_DIR=/tmp/act-leases/audit-bus
export CONSUMER_AUDIT_LOG=/tmp/act-leases/audit.log
export CONSUMER_AUDIT_CHAIN_HEAD=/tmp/act-leases/audit-chain-head
export CONSUMER_SIGNING_KEY_FILE=/tmp/act-leases/signing.key
export POLL_INTERVAL_SECONDS=30
```

For production deployments, point these at durable locations
(e.g. `/var/spool/act-leases/...`).

## Honest limitations

- **Revocation is forensic, not a deny-list.** When a lease is
  revoked, an audit event is emitted. The verifier itself doesn't
  consult a revocation list — TTL expiry is the canonical
  revocation surface. Explicit `revoke_lease()` is for compromise
  response and audit trails, not runtime denial. A full
  revocation-list verifier is straightforward to add (poll an
  audit-log of revoke events before accepting) but is out of
  scope for the reference implementation.
- **Trust-on-first-use for unknown signers.** The verifier
  lazy-registers any signer whose signature verifies. This means
  if you can present a valid signature, you're in. For high-
  security deployments, replace the lazy-register path with a
  pre-distributed trust store.
- **No revocation tree or freshness protocol.** Chains are
  append-only; there is no witness layer integrated into the
  verifier. Compose with an external witness / heartbeat
  protocol for unattended-detection.

## License

MIT. See `LICENSE`.
