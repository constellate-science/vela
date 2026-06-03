import Lake
open Lake DSL

package vela_theorems where
  version := v!"0.1.0"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.29.1"

lean_lib Vela where
