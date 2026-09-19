package sql

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"
)

// FingerprintVersion identifies the structural fingerprint format produced by
// Fingerprint and FingerprintString. It is emitted as the prefix of every
// fingerprint, separated from the digest by a colon (e.g. "v1:3f8a...").
//
// The version is bumped whenever the normalization rules or the set of
// covered AST nodes change in a way that could alter previously computed
// fingerprints, so fingerprints are only comparable within the same version.
const FingerprintVersion = "v1"

// fingerprintDigestSize is the number of SHA-256 bytes emitted in a
// fingerprint. 128 bits keeps fingerprints short enough for use as metric
// label values while making accidental collisions negligible.
const fingerprintDigestSize = 16

// ErrFingerprintUnhandled is returned, wrapped, by Fingerprint when a
// statement contains an AST node or struct field that the current
// fingerprint format does not cover. This happens when the AST is extended
// with new node types (or new field kinds on existing nodes) that
// fingerprinting has not been taught about yet. No fingerprint is produced
// in that case: the failure is loud on purpose so that a partially
// fingerprinted statement can never silently reuse an older fingerprint.
var ErrFingerprintUnhandled = errors.New("sql: fingerprint: unhandled AST element")

// Fingerprint returns a stable structural fingerprint of stmt, suitable for
// aggregating statements by shape in metrics and observability pipelines.
//
// The fingerprint is insensitive to changes that do not alter the structure
// of the statement:
//
//   - whitespace and comments (never reach the AST),
//   - the contents of number, string, blob and timestamp literals,
//   - the names of bind parameters (?, ?NNN, :name, @name and $name are
//     all equivalent),
//   - the case of unquoted identifiers (SQLite folds ASCII case).
//
// Changes to table names, column names, operators, join kinds, subquery
// structure or statement type always change the fingerprint. Quoted
// identifiers keep SQLite identifier semantics: a double-quoted "Foo" and
// "foo" are distinct and are not folded.
//
// The statement is never modified: Fingerprint walks a deep copy of the
// AST, so it is safe to call Fingerprint concurrently from multiple
// goroutines on the same statement. If stmt contains an AST element that
// the current fingerprint format does not cover, an error wrapping
// ErrFingerprintUnhandled is returned and no fingerprint is produced.
func Fingerprint(stmt Statement) (string, error) {
	if stmt == nil {
		return "", errors.New("sql: fingerprint: cannot fingerprint a nil statement")
	}

	// Walk writes visited nodes back into the tree, so operate on a deep
	// copy to keep the caller's AST untouched and safe for concurrent use.
	clone, err := cloneStatementForFingerprint(stmt)
	if err != nil {
		return "", err
	}

	v := &fingerprintVisitor{h: sha256.New()}
	if _, err := Walk(v, clone); err != nil {
		return "", err
	}
	sum := v.h.Sum(nil)
	return FingerprintVersion + ":" + hex.EncodeToString(sum[:fingerprintDigestSize]), nil
}

// FingerprintString parses sql, which may contain multiple statements, and
// returns one fingerprint per statement, in the order the statements appear.
// See Fingerprint for the normalization rules.
//
// If the input cannot be parsed, the parse error is returned and no
// fingerprints are produced.
func FingerprintString(s string) ([]string, error) {
	stmts, err := NewParser(strings.NewReader(s)).ParseStatements()
	if err != nil {
		return nil, err
	}
	fps := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		fp, err := Fingerprint(stmt)
		if err != nil {
			return nil, err
		}
		fps = append(fps, fp)
	}
	return fps, nil
}

// cloneStatementForFingerprint deep-copies stmt. CloneStatement panics on
// statement types it does not know; convert that failure into an error so
// that unsupported statements fail loudly instead of crashing the caller.
func cloneStatementForFingerprint(stmt Statement) (clone Statement, err error) {
	defer func() {
		if r := recover(); r != nil {
			clone, err = nil, fmt.Errorf("%w: %v", ErrFingerprintUnhandled, r)
		}
	}()
	clone = CloneStatement(stmt)
	if clone == nil {
		return nil, fmt.Errorf("%w: cannot clone statement of type %T", ErrFingerprintUnhandled, stmt)
	}
	return clone, nil
}

// fingerprintVisitor is a read-only Visitor that streams a canonical
// structural description of an AST into a hash. It reuses Walk for
// traversal; node types whose children Walk does not descend into are
// handled explicitly in Visit.
type fingerprintVisitor struct {
	h hash.Hash
}

// Compile-time assertion that fingerprintVisitor implements Visitor.
var _ Visitor = (*fingerprintVisitor)(nil)

// Visit records n and, for node types not descended into by Walk, walks
// their children explicitly. It never modifies n.
func (v *fingerprintVisitor) Visit(n Node) (Visitor, Node, error) {
	if n == nil || (reflect.ValueOf(n).Kind() == reflect.Ptr && reflect.ValueOf(n).IsNil()) {
		return nil, nil, errors.New("sql: fingerprint: cannot fingerprint a nil node")
	}

	v.write("(" + reflect.TypeOf(n).String())

	switch n := n.(type) {
	case *Ident:
		// SQLite folds ASCII case of unquoted identifiers, while quoted
		// identifiers remain case-sensitive.
		if n.Quoted {
			v.writef(";Q=%q", n.Name)
		} else {
			v.writef(";U=%q", asciiFoldUpper(n.Name))
		}
	case *StringLit, *NumberLit, *BlobLit, *TimestampLit:
		// Literal contents are normalized away; only the literal kind is
		// recorded (via the node type written above).
		v.write(";lit")
	case *NullLit:
		// NULL carries no value.
	case *BoolLit:
		v.writef(";v=%t", n.Value)
	case *BindExpr:
		// Bind parameter names are normalized away.
	case *WithClause:
		// Walk does not descend into CTEs, and CTE is not a Node, so
		// frame each CTE explicitly.
		v.writef(";Recursive=%t", n.Recursive.IsValid())
		for _, cte := range n.CTEs {
			v.write("(sql.CTE")
			if err := v.writeScalars(cte); err != nil {
				return nil, nil, err
			}
			if err := v.walkChild(cte.TableName); err != nil {
				return nil, nil, err
			}
			for _, col := range cte.Columns {
				if err := v.walkChild(col); err != nil {
					return nil, nil, err
				}
			}
			if err := v.walkChild(cte.Select); err != nil {
				return nil, nil, err
			}
			v.write(")")
		}
	case *Null:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.X); err != nil {
			return nil, nil, err
		}
	case *CollateConstraint:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Name); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Collation); err != nil {
			return nil, nil, err
		}
	case *PragmaStatement:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Schema); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Expr); err != nil {
			return nil, nil, err
		}
	case *ReindexStatement:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Name); err != nil {
			return nil, nil, err
		}
	case *ModuleArgument:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Name); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Literal); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Type); err != nil {
			return nil, nil, err
		}
	case *CreateVirtualTableStatement:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Schema); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.Name); err != nil {
			return nil, nil, err
		}
		if err := v.walkChild(n.ModuleName); err != nil {
			return nil, nil, err
		}
		for _, arg := range n.Arguments {
			if err := v.walkChild(arg); err != nil {
				return nil, nil, err
			}
		}
	case SelectExpr:
		// Walk does not descend into a SELECT used as an expression.
		if err := v.walkChild(n.SelectStatement); err != nil {
			return nil, nil, err
		}
	case *AlterTableStatement, *AnalyzeStatement, *Assignment, *BeginStatement,
		*BinaryExpr, *Call, *CaseBlock, *CaseExpr, *CastExpr, *CheckConstraint,
		*CollateExpr, *ColumnDefinition, *CommitStatement, *CreateIndexStatement,
		*CreateTableStatement, *CreateTriggerStatement, *CreateViewStatement,
		*DefaultConstraint, *DeleteStatement, *DropIndexStatement,
		*DropTableStatement, *DropTriggerStatement, *DropViewStatement, *Exists,
		*ExplainStatement, *ExprList, *FilterClause, *ForeignKeyArg,
		*ForeignKeyConstraint, *FrameSpec, *GeneratedConstraint, *IndexedColumn,
		*InsertStatement, *JoinClause, *JoinOperator, *NotNullConstraint,
		*OnConstraint, *OrderingTerm, *OverClause, *ParenExpr, *ParenSource,
		*PrimaryKeyConstraint, *QualifiedRef, *QualifiedTableFunctionName,
		*QualifiedTableName, *Raise, *Range, *ReleaseStatement, *ResultColumn,
		*ReturningClause, *RollbackStatement, *SavepointStatement,
		*SelectStatement, *Type, *UnaryExpr, *UniqueConstraint, *UpdateStatement,
		*UpsertClause, *UsingConstraint, *Window, *WindowDefinition:
		if err := v.writeScalars(n); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("%w: node type %T", ErrFingerprintUnhandled, n)
	}
	return v, n, nil
}

// VisitEnd closes the structural frame opened by Visit.
func (v *fingerprintVisitor) VisitEnd(n Node) (Node, error) {
	v.write(")")
	return n, nil
}

// walkChild walks a child node with this visitor. Nil children are skipped.
func (v *fingerprintVisitor) walkChild(n Node) error {
	if n == nil {
		return nil
	}
	if rv := reflect.ValueOf(n); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil
	}
	_, err := Walk(v, n)
	return err
}

var (
	posType   = reflect.TypeOf(Pos{})
	tokenType = reflect.TypeOf(Token(0))
	nodeType  = reflect.TypeOf((*Node)(nil)).Elem()
)

// writeScalars records every scalar field of the struct node x: keyword
// presence (Pos validity), operators (Token values) and flags (bools).
// Child nodes are skipped because they are covered by tree traversal.
// String fields and unrecognized field kinds are rejected so that new AST
// surface area fails loudly instead of being silently fingerprinted.
func (v *fingerprintVisitor) writeScalars(x interface{}) error {
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("%w: node %T is not a struct", ErrFingerprintUnhandled, x)
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f, fv := rt.Field(i), rv.Field(i)
		switch ft := f.Type; {
		case ft == posType:
			v.writef(";%s=%t", f.Name, fv.Interface().(Pos).IsValid())
		case ft == tokenType:
			v.writef(";%s=%d", f.Name, fv.Interface().(Token))
		case ft.Kind() == reflect.Bool:
			v.writef(";%s=%t", f.Name, fv.Bool())
		case ft.Kind() == reflect.String:
			return fmt.Errorf("%w: string field %s.%s", ErrFingerprintUnhandled, rt.Name(), f.Name)
		case ft.Implements(nodeType), ft.Kind() == reflect.Interface:
			// Child node; covered by tree traversal.
		case ft.Kind() == reflect.Slice && (ft.Elem().Implements(nodeType) || ft.Elem().Kind() == reflect.Interface):
			// Child node slice; covered by tree traversal.
		default:
			return fmt.Errorf("%w: field %s.%s of type %s", ErrFingerprintUnhandled, rt.Name(), f.Name, ft)
		}
	}
	return nil
}

// write streams s into the fingerprint hash.
func (v *fingerprintVisitor) write(s string) {
	v.h.Write([]byte(s)) // hash.Hash never returns an error
}

// writef streams a formatted string into the fingerprint hash.
func (v *fingerprintVisitor) writef(format string, args ...interface{}) {
	fmt.Fprintf(v.h, format, args...)
}

// asciiFoldUpper folds ASCII letters to upper case, mirroring SQLite's
// case-insensitive comparison of unquoted identifiers. Bytes outside the
// ASCII range are left untouched.
func asciiFoldUpper(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			b := []byte(s)
			b[i] = c - ('a' - 'A')
			for i++; i < len(s); i++ {
				if c := s[i]; c >= 'a' && c <= 'z' {
					b[i] = c - ('a' - 'A')
				}
			}
			return string(b)
		}
	}
	return s
}
