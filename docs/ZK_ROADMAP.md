# Zero-knowledge receipts - design & roadmap

The selective-disclosure receipt (commitment + witness) lets an operator prove soundness for the
actions they *reveal*. The ZK step removes the trade-off: prove that a hidden action satisfied the
committed policy **without revealing the action at all**. This is where the founder's ZK stack
(Groth16 / Nova / BLS, and `proof-of-inference`) plugs in.

This doc scopes it so the crypto is built deliberately and reviewed - not rushed into a security repo.

## The predicate to prove

For each entry, prove in zero knowledge:

> "I know an action `A` and salt `s` such that `commit == SHA256(canonical(A) || s)`, and
> `policy(A) == V`" - where `commit`, the policy commitment, and the recorded verdict `V` are public,
> and `A` and `s` stay hidden.

A verifier then gets the *same* guarantee as the soundness re-run (the recorded verdict is correct for
the committed action) with **zero disclosure**. It composes cleanly with the current receipt: replace
"disclose the action" with "attach a ZK proof"; the chain, the signature, and the identity binding are
unchanged.

## Tractable scope first: the git-branch sub-policy

Do not attempt the full ruleset first. The shell/secret rules are regex over unbounded strings - a
genuine SNARK-over-regex problem, expensive and error-prone. The **git-branch policy is the right first
target**, for the same reason it is the one already z3-checked:

- Its domain is small and structured: `op ∈ {push, reset, rebase, commit, branch, ...}`, `branch` from
  a finite protected set (else "other"), `force ∈ {0,1}`, `hard ∈ {0,1}`.
- Its logic is a handful of booleans (`op=push ∧ protected ∧ force ⇒ BLOCK`, etc.).
- So `policy(A) == V` is a tiny arithmetic/boolean circuit, and set membership over the allowed
  `(A, V)` pairs is small.

Ship ZK for the git-branch sub-policy; keep commitment+witness selective disclosure for the rest. State
that split honestly (mirrors the existing "proven vs heuristic" table).

## Two implementation paths

1. **Sigma-protocol OR-proof (no heavy toolchain, Python).** Because the allowed `(A, V)` set for the
   git-branch policy is small and enumerable, prove "the committed action is one of the elements of the
   set `S_V = { A : policy(A) = V }`" with a Fiat-Shamir OR-composition over Pedersen commitments
   (`py_ecc` / an ed25519- or BLS12-381-based group). Real ZK, ~200 lines, but **easy to get subtly
   wrong** (challenge splitting, the simulator) - needs careful tests for *soundness* (a false claim
   cannot produce a valid proof) and *zero-knowledge* (the transcript is simulatable without the
   witness) plus, ideally, an external review before it ships.
2. **SNARK (Groth16/Nova) over a small circuit.** Express `commit == H(A‖s) ∧ policy(A) == V` as a
   circuit and prove with the existing `proof-of-inference` proving stack. Heavier (a hash in-circuit),
   but the honest path to eventually covering more of the policy, and reuses code the founder already has.

Recommendation: prototype path 1 for the git-branch sub-policy to prove the UX and the interface, then
move to path 2 if/when a customer or underwriter needs it at scale.

## Interface (unchanged receipt, new proof field)

- `Entry` gains an optional `zk_proof` alongside `commit`. A redacted entry with a `zk_proof` is
  verified for soundness *without* an action or witness.
- `verify_receipt` gains a ZK verifier: for entries with a `zk_proof`, check the proof against
  `(commit, policy_commitment, verdict)`; count them as "sound" in the coverage line exactly like a
  disclosed action.
- `redact()` can attach proofs instead of stripping to nothing, giving "fully private AND fully sound".

## Milestones

1. **DONE** - Sigma OR-proof for the git-branch policy (`qedra/zk.py`, `tests/test_zk.py`,
   `demo_zk.py`). CDS OR-composition of Schnorr statements over Pedersen commitments in the order-Q QR
   subgroup of the RFC 3526 2048-bit safe prime (the group is re-checked at test time via Miller-Rabin,
   so a bad constant fails loudly). 12/12 tests: correctness, soundness (the strongest witness-free
   cheat `simulate_all` is rejected; a verdict relabel and a wrong commitment are rejected), and
   honest-verifier zero-knowledge (transcripts are simulatable without the witness). Gate met: honest
   proofs verify, forged verdicts cannot be proven, transcripts are simulatable.
   Benchmark (pure-Python, 24-clause BLOCK set): prove ~1.1 s, verify ~1.1 s, proof ~43 KB
   (~1.8 KB/clause). The cost is 2048-bit modexp in CPython; a 256-bit elliptic-curve group (milestone 4)
   would cut both time and size by ~1-2 orders of magnitude. Adequate for the prototype's purpose:
   prove the UX and the interface.
2. **DONE** - Wired into `Entry.zk` + `verify_receipt` (`control_plane.py`, `tests/test_zk_receipt.py`,
   `demo_zk_receipt.py`). Resolution of the binding problem: in zk-mode (`ControlPlane(..., zk=True)`)
   a git-branch entry's chain commitment IS the decimal Pedersen `C`, and the eager ZK proof is over
   that same `C`, so the proof speaks about the exact action that was chained; there is no second
   commitment to reconcile. The proof is zero-knowledge, so it is carried even in a full receipt and
   simply survives redaction (which strips only the action + randomness). The entry's reason is generic
   (`git-branch policy: <verdict>`) so redaction leaks nothing via the reason. `verify_receipt` verifies
   the proof over `C`, and for a *disclosed* zk entry additionally re-derives `C` from the revealed
   action to bind it. 8/8 tests incl. the load-bearing one: a chained BLOCK cannot be relabelled ALLOW
   even by re-chaining + re-signing with the operator's own key, because no ALLOW proof exists over a
   BLOCK commitment. Non-git actions keep the sha-256 commitment; default mode (`zk=False`) is unchanged.
3. External review of the crypto before it is presented as a guarantee.
4. **Group is now pluggable; secp256k1 done (`ec.py`, `zk_ec.py`, `tests/test_zk_ec.py`).** The OR-proof
   core was extracted group-agnostic (`zk_core.py`); the MODP scheme (`zk.py`) and an elliptic-curve
   scheme (`zk_ec.py`, secp256k1) are both thin group definitions over it, sharing the entire proof
   core and policy layer. `ec.py` is pure-Python secp256k1 (affine reference + Jacobian fast path,
   cross-validated against each other and against published KAT vectors in `self_check`, so a bad
   constant or arithmetic bug fails loudly). Measured, same 24-clause BLOCK proof: **EC ~10x faster
   prove/verify (~110 ms vs ~1.1 s) and ~8x smaller (~5.6 KB vs ~44 KB)**. 10/10 EC tests mirror the
   MODP property tests (correctness, soundness, ZK, serialization). Note: the affine path alone is
   *slower* than MODP in Python (per-step inverse); the Jacobian path is what delivers the speed. EC is
   standalone groundwork, `control_plane` still defaults to MODP; switching it is a one-line group
   swap once the crypto is externally reviewed (milestone 3).

   The zk domain (the protected-branch set) parameterises on the policy's `PolicySpec`, so
   zero-knowledge receipts work over a *custom* protected set, not only the built-in one: the prover
   passes its set, and the verifier recomputes the allowed-set from the spec it holds (which the policy
   root binds). The encoding abstracts a branch to (protected-index, force, hard), so a proof attests to
   the protected-ness structure and verdict; the specific branch name is bound by the disclosed action
   or is simply not needed for a redacted entry.

   Still later / demand-driven: a SNARK path via `proof-of-inference` to widen beyond the git-branch
   policy (regex/shell rules), and binding a native curve library for production-grade speed.

## Honest limits

- ZK here proves *policy satisfaction over the committed action*, not the model's intent - the same
  boundary as the plaintext receipt (see `CONTROL_PLANE_TRUST_MODEL.md`).
- Regex/shell rules over unbounded input are out of scope for the first version; they stay on
  commitment+witness selective disclosure.
- Do not present a ZK receipt as a guarantee until milestone 3. Broken ZK in a security tool is worse
  than no ZK.
