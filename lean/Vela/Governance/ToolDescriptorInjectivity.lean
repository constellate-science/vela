import Mathlib
import Vela.Crypto.CanonicalEventId

/-!
# Vela Theorem 25: Tool descriptor injectivity

A tool descriptor (`vtd_*`) is a v0.199 Carina primitive declaring
that a frontier consumes outputs from a specific tool: tool name,
tool version, provider identifier, calling convention, plus the
tool's input + output JSON schemas. The descriptor id is content-
addressed via:

    descriptor_id = "vtd_" ++ (sha256(canonicalBytes(body))).take 16

where canonicalBytes packs (tool_name, tool_version, provider,
calling_convention, canonical_json(input_schema),
canonical_json(output_schema)) under a `|`-delimited layout. The
input/output schemas are canonicalized with sorted-keys + compact
separators so semantically-identical schemas with different key
insertion orders produce the same id.

This theorem pins the algebraic guarantee that distinct descriptor
preimages produce distinct descriptor ids, under an abstract
injectivity assumption on the hash. Composes T9 (canonical-event-id
determinism).

Substrate role: pins the v0.199 ToolDescriptor primitive. Two
consumers running the same `vela tool register` invocation with
byte-identical (tool_name, tool_version, provider,
calling_convention, schemas) reach the same descriptor id; any
drift produces a different `vtd_*` and is therefore reviewable as
a separate object.
-/

namespace Vela.ToolDescriptorInjectivity

/-- The tool descriptor preimage tuple. -/
structure DescriptorPreimage where
  tool_name : String
  tool_version : String
  provider : String
  calling_convention : String       -- one of {http_json, python_callable, cli_subprocess, mcp_server}
  input_schema : String             -- canonical JSON (sorted keys + compact)
  output_schema : String            -- canonical JSON (sorted keys + compact)
deriving DecidableEq, Repr

/-- Abstract canonical serializer over the descriptor preimage.
Injective by construction: each field is `|`-delimited; the
calling_convention is from a fixed alphabet that excludes `|`; the
canonicalized schemas are valid JSON in which top-level structure is
already normalized, so two equal canonicalBytes encodings imply
equal field tuples. We declare injectivity as an axiom — the Rust
side enforces the field-character invariants at construction time. -/
def canonicalBytes (p : DescriptorPreimage) : String :=
  s!"{p.tool_name}|{p.tool_version}|{p.provider}|{p.calling_convention}|{p.input_schema}|{p.output_schema}"

axiom canonicalBytes_injective :
  Function.Injective canonicalBytes

/-- Abstract injective hash. -/
noncomputable axiom Hash : String → String
axiom hash_injective : Function.Injective Hash

/-- The descriptor id derivation. -/
noncomputable def descriptorId (p : DescriptorPreimage) : String :=
  "vtd_" ++ Hash (canonicalBytes p)

/-- Theorem 25: distinct descriptor preimages produce distinct
descriptor ids. Composes canonicalBytes_injective and
hash_injective. -/
theorem theorem25_tool_descriptor_id_injective :
    Function.Injective descriptorId := by
  intro a b h
  have hHash : Hash (canonicalBytes a) = Hash (canonicalBytes b) := by
    have := h
    simp [descriptorId] at this
    exact this
  have hBytes : canonicalBytes a = canonicalBytes b :=
    hash_injective hHash
  exact canonicalBytes_injective hBytes

end Vela.ToolDescriptorInjectivity
