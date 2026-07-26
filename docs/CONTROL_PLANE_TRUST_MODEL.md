# Agent Control Plane — what a verified receipt guarantees

This is the document a security reviewer, an auditor, or an insurer should read before relying on an
Agent Control Plane receipt. It states precisely what a `VERIFIED` result proves, what it does not, and
the assumptions it rests on. It deliberately does not overclaim: a receipt is measurement provenance for
an agent's gated actions, not a proof that the agent (or the model behind it) is "safe".

## What `verify_receipt` -> VERIFIED proves

For a receipt that verifies against a policy the relying party holds (and, with `--registry`, a pinned
public key), all of the following hold:

1. **Policy identity.** The trace was gated under the exact policy the verifier holds: the receipt's
   `policy_root` equals `Policy(id, version).root()`. A receipt issued under a different policy is
   rejected.
2. **Integrity.** The recorded action trace is untampered. The public SHA-256 hash-chain is recomputed
   from genesis; any inserted, deleted, reordered, or altered entry breaks it. No key is needed for
   this check — anyone can recompute it.
3. **Authenticity.** The Ed25519 signature over the chain head is valid for the receipt's key, and (with
   a registry or `--pin-key`) that key is the one pinned to the claimed `agent_id`. An attacker who
   signs a compliant trace but impersonates a registered identity is rejected.
4. **Soundness (the load-bearing check).** Re-running the committed policy over each recorded action
   reproduces the recorded verdict. So a receipt that claims `ALLOW` for an action the policy would
   `BLOCK` fails — **even when the operator recomputed the chain and re-signed with their own key.**
   An honest receipt and a forged one are cryptographically distinguishable by anyone.
5. **Enforcement.** No action recorded as `BLOCK` is marked executed.

In short: *within the gated tool-call path, under this named policy, this exact sequence of actions was
evaluated, these were the verdicts, and the blocked ones did not run — provably, to a third party who
trusts neither the operator nor the server.*

## What it does NOT prove

- **Not the model's intent or "safety".** The receipt says nothing about whether the agent's reasoning
  was correct or benign — only what actions it emitted and how the policy scored them.
- **Not that the policy is complete.** The guarantee is relative to the committed policy. If the policy
  has a gap (a threat it does not encode), a harmful-but-allowed action verifies as compliant. The
  policy is auditable and its git-branch sub-policy is z3-checked, but the ruleset is otherwise
  high-precision heuristics (see the main README's "proven vs heuristic" table).
- **Not actions taken outside the gate.** The receipt covers only calls that went through the Control
  Plane. If the agent has another execution path (an unguarded shell, or the ability to edit the gate),
  those actions are neither gated nor in the receipt. See `THREAT_MODEL.md`.
- **Not the truth of the inputs.** Like any attestation, it proves the gate reported faithfully on the
  actions it saw; it cannot prove the environment fed the agent honest data.

## Trust assumptions

- **The gate runs out-of-process from the agent.** If the agent can read the signing key or modify the
  gate/policy, it can forge or bypass. Run the Control Plane as a separate process/service; give the
  agent no other route to shell, files, or git. This is the same assumption as the gate itself.
- **Key custody.** The Ed25519 signing key is the agent operator's; the receipt is only as trustworthy
  as that key not being available to the agent. Persist it (`GUARDRAIL_SIGNING_KEY`) so a relying party
  can pin one identity across sessions.
- **The registry is a trust root the *verifier* holds.** Pinning `agent_id -> public key` must happen
  out-of-band and be under the relying party's control; it is intentionally not signed by the operator
  (that would be circular), exactly like a CA's registration or SSH `known_hosts`.
- **The verifier independently holds the policy.** The soundness re-run is only meaningful because the
  verifier reconstructs the policy themselves; taking the policy on the receipt's word makes check 1
  vacuous. Ship the policy definition to relying parties, versioned.

## Privacy: redaction and selective disclosure

The chain is over a salted commitment of each action, not the raw action, so a receipt can be redacted
without invalidating its signature or integrity. `receipt.redact(reveal=...)` strips the raw commands
and file contents (which would otherwise leak secrets and internal state) and returns a witness holding
the redacted `(action, salt)` pairs. The operator can then disclose any subset to a verifier.

- A **redacted** receipt (no witness) proves policy identity, integrity, authenticity, and the
  enforcement invariant — but NOT soundness, because the verifier cannot re-run the policy on hidden
  actions. `verify_receipt` reports the coverage (`N disclosed and sound, M redacted`) so this is never
  mistaken for a full guarantee.
- A **witness** (full or partial) restores the soundness re-run for exactly the disclosed actions; a
  disclosed action whose content does not match its commitment is rejected.

This is commitment-based selective disclosure. A zero-knowledge proof of "the hidden action satisfied
the committed policy" (proving soundness *without* disclosure) is the natural next step and does not
change this trust model's guarantees, only how much must be revealed to obtain them.

## Attacks defeated vs. out of scope

| Attempt | Result |
|---|---|
| Alter/insert/delete/reorder a recorded action | caught (chain integrity) |
| Claim ALLOW for a would-be-BLOCK action, re-chain + re-sign with the operator's key | caught (soundness re-run) |
| Sign a compliant trace but impersonate a registered agent | caught (pinned key mismatch) |
| Issue under a different/weaker policy and hope the verifier does not notice | caught (policy commitment) if the verifier supplies the policy they expect |
| Take a harmful action the policy does not encode | NOT caught — it is a policy gap, and the receipt honestly records it as allowed |
| Take an action outside the gated path (unguarded shell, editing the gate) | NOT covered — outside the Control Plane's remit; pair with process isolation |

## The honest one-liner

A verified receipt is proof of **policy-compliant, tamper-evident, agent-attributable action provenance**
over the gated path — nothing more, and nothing less. That is a real and currently-unmet primitive for
anyone who has to trust what an autonomous agent did without having been in the room. It is not a safety
certificate for the agent.
