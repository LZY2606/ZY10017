sql
===

[![Circle CI](https://circleci.com/gh/rqlite/sql/tree/master.svg?style=svg)](https://app.circleci.com/pipelines/github/rqlite/sql)

This repository holds a pure Go SQL parser based on the [SQLite](https://sqlite.org/) SQL definition. It implements nearly all features of the language except `ATTACH`, `DETACH`, and some other minor features.

## Example Usage

```Go
parser := NewParser(strings.NewReader("SELECT * FROM foo WHERE id=4"))
expr, _ = parser.Parse()
fmt.Println(expr)
```

Review the unit tests in `parser_test.go` for an extensive set of parsing examples.

## Structural Fingerprints

`Fingerprint` and `FingerprintString` compute stable structural fingerprints
of statements for metrics aggregation: whitespace, comments, literal
contents and bind parameter names are normalized away, while table names,
column names, operators, join kinds, subquery structure and statement type
all affect the result. See [FINGERPRINT.md](FINGERPRINT.md) for the format,
versioning and failure-mode contract.

## Credits
This parser was originally created by [Ben Johnson](https://github.com/benbjohnson). Many thanks to him for making it available for use by [rqlite](https://rqlite.io).
