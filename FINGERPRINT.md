# Structural Fingerprints

`Fingerprint` and `FingerprintString` (see `fingerprint.go`) compute a
stable structural fingerprint of SQL statements so that observability
pipelines can aggregate statements by shape without copying user literals
or bind values into metric labels.

## Format

A fingerprint is `<version>:<digest>`, e.g. `v1:3f8ac1...`.

- **Version prefix.** `FingerprintVersion` (currently `v1`) identifies the
  normalization rules and the set of covered AST nodes. It is bumped
  whenever a change could alter previously computed fingerprints.
  Fingerprints are only comparable within the same version.
- **Digest.** The first 128 bits of SHA-256 over a canonical structural
  encoding of the AST, hex-encoded (32 characters).

## Normalization rules (v1)

These do **not** change the fingerprint:

- whitespace and comments,
- the contents of number, string, blob and timestamp literals,
- bind parameter names (`?`, `?NNN`, `:name`, `@name`, `$name`),
- the case of unquoted identifiers (SQLite folds ASCII case).

These **always** change the fingerprint:

- table names, column names and aliases,
- operators, join kinds, sort directions, `DISTINCT`/`ALL`, etc.,
- subquery structure, CTE structure, window definitions,
- statement type,
- quoted identifiers, which keep SQLite identifier semantics: `"Foo"` and
  `"foo"` are distinct and are never folded.

## Failure mode for unhandled AST elements

Fingerprinting fails loudly. If the AST is extended with a node type (or a
field kind on an existing node) that the current format does not cover,
`Fingerprint` returns an error wrapping `ErrFingerprintUnhandled` and
produces **no** fingerprint. It never silently falls back to an older or
partial fingerprint. The fix is to teach `fingerprintVisitor` about the new
element and bump `FingerprintVersion`.

## Concurrency

`Fingerprint` walks a deep copy of the statement and keeps all state
per-call, so it never modifies the AST and is safe for concurrent use on
shared statements.
