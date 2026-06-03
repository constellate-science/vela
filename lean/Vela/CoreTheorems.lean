import Vela.Provenance
import Vela.Transfer
import Vela.TransferCWCtoDNA
import Vela.TransferPackingToCWC
import Vela.TransferBinaryCodeToCWC
import Vela.TransferPackingToDisjunct
import Vela.TransferCostasToGolomb
import Vela.TransferHadamardToCWC
import Vela.TransferOAtoCWC
import Vela.TransferClassicalToCSS
import Vela.TransferMDSToSecretSharing
import Vela.TransferHypergraphProduct
import Vela.TransferHypergraphProductRing
import Vela.TransferLiftedProduct
import Vela.ReducerModel
import Vela.Core
import Vela.PoVD
import Vela.Accumulation
import Vela.HeteroAccumulation
import Vela.ProtocolKeystone
import Vela.FoldingSoundness
import Vela.SumcheckSoundness
import Vela.Log
import Vela.Signing
import Vela.ReplayIndex
import Vela.EGZ
import Vela.CanonicalEventId
import Vela.SignatureUniqueness
import Vela.MultiSigThreshold
import Vela.ConcurrentReplay
import Vela.FrontierIdDeterminism
import Vela.ProposalIdempotency
import Vela.ConfidenceUpdate
import Vela.GovernedQuorumSoundness
import Vela.SearchIndexDeterminism
import Vela.OwnerEpochChainMonotonicity
import Vela.CheckpointRootInjectivity
import Vela.EmptyLogReplay
import Vela.CanonicalSequenceLength
import Vela.ReplayAppend
import Vela.ScientificDiffPackId
import Vela.AgentAttestationInjectivity
import Vela.ToolDescriptorInjectivity
import Vela.DiffPackVerdictAtomicity
import Vela.EvaluationRecordInjectivity
import Vela.ToolDescriptorComposition
import Vela.ReleasedDiffPackAccumulation
import Vela.DiffPackFederationSoundness
import Vela.VerdictConflictResolution
import Vela.VerdictConflictAccumulation
import Vela.ReleasedDiffPackReplay
import Vela.EvaluationDescriptorComposition

/-!
# Vela core theorem bundle

This module imports the machine-checked substrate theorems for Vela:

- `Vela.Provenance`: substrate Theorems 2, 3, and 4.
- `Vela.Transfer`: the constellation layer -- substrate Theorem 23 (cross-frontier transfer
  soundness) plus the category structure on frontiers (Mathlib-free; compiles standalone).
- `Vela.ReducerModel`: a CONCRETE event-sourced reducer with PROVEN invariants (replay
  determinism + append law + append-only log + descriptor preservation), de-hollowing the
  assume-guarantee descriptor theorems (Mathlib-free; compiles standalone).
- `Vela.Core`: the DEPENDENCY-FREE nucleus -- substrate
  Theorems 2,3,4 re-proven over plain `List` with NO Mathlib, so the core invariants verify in
  seconds via `lean Vela/Core.lean` (with Transfer + ReducerModel, also Mathlib-free).
- `Vela.PoVD`: Proof-of-Verified-Delta -- a permissionless accumulation mechanism for the
  verifiable slice, with machine-checked anti-gaming properties (no credit without verification,
  monotone state, no double-spend, Sybil/duplication resistance). Mathlib-free.
- `Vela.Log`: substrate Theorems 1 and 5.
- `Vela.Signing`: Theorem 6 (v0.104 multi-sig canonical-bytes fix).
- `Vela.ReplayIndex`: Theorem 7 (v0.105 O(N) replay index maintenance).
- `Vela.EGZ`: Theorem 8 (Erdős-Ginzburg-Ziv 1961, n = 2 case).
- `Vela.CanonicalEventId`: Theorem 9 (canonical-event-id determinism).
- `Vela.SignatureUniqueness`: Theorem 10 (signature uniqueness under canonical bytes).
- `Vela.MultiSigThreshold`: Theorem 11 (multi-sig threshold soundness).
- `Vela.ConcurrentReplay`: Theorem 12 (concurrent-replay commutativity for disjoint events).
- `Vela.FrontierIdDeterminism`: Theorem 13 (frontier-id determinism).
- `Vela.ProposalIdempotency`: Theorem 14 (proposal-acceptance idempotency).
- `Vela.ConfidenceUpdate`: Theorem 15 (confidence-update bounds).
- `Vela.GovernedQuorumSoundness`: Theorem 16 (governed-quorum soundness).
- `Vela.SearchIndexDeterminism`: Theorem 17 (search-index determinism).
- `Vela.OwnerEpochChainMonotonicity`: Theorem 18 (owner-epoch chain monotone-by-one).
- `Vela.CheckpointRootInjectivity`: Theorem 19 (registry-checkpoint root injectivity).
- `Vela.EmptyLogReplay`: Theorem 20 (empty-log replay identity — base case of replay convergence).
- `Vela.CanonicalSequenceLength`: Theorem 21 (canonical-sequence cardinality preservation).
- `Vela.ReplayAppend`: Theorem 22 (replay-compositional append; incremental-replay legitimacy).

It is intended as the single import target for downstream documentation and
experiments.
-/
