import Vela.CoreTheorems
-- Reference verification certificate (vcert): a kernel-checked witness
-- for the OEIS A309370 lower bound a(8) ≥ 33. The Lean kernel re-derives
-- pairwise-sum distinctness independently of the Python/Rust verifiers.
import Vela.Constructions.SidonCertificate
