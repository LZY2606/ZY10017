package sql

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// FingerprintVersionV1 is the prefix of structural fingerprints produced by
// the v1 canonical AST encoding.
const FingerprintVersionV1 = "rqlite-sql-fp1:"

// ErrUnsupportedFingerprintNode reports that an AST node was not encoded by
// the current fingerprint version. New AST nodes must extend the canonical
// encoding and typically introduce a new fingerprint version instead of
// allowing this node to be silently ignored.
var ErrUnsupportedFingerprintNode = errors.New("unsupported fingerprint AST node")

// Fingerprint returns a stable structural fingerprint for a parsed statement.
// Whitespace, comments, numeric, string and blob literal contents, and bind
// parameter names do not affect the result. Identifiers retain SQLite
// semantics: they are case-folded whether quoted or not, while string
// literals remain a distinct node kind.
//
// Fingerprint is safe for concurrent use on the same AST and does not modify
// stmt. If the AST contains a node not supported by FingerprintVersionV1,
// Fingerprint returns an error wrapping ErrUnsupportedFingerprintNode rather
// than calculating an incomplete fingerprint.
func Fingerprint(stmt Statement) (string, error) {
	if stmt == nil {
		return "", fmt.Errorf("sql: cannot fingerprint nil statement")
	}
	if err := checkFingerprintNode(stmt); err != nil {
		return "", err
	}

	enc := newFingerprintEncoder()
	if _, err := Walk(enc, stmt); err != nil {
		return "", err
	}

	sum := sha256.Sum256(enc.buf)
	return FingerprintVersionV1 + hex.EncodeToString(sum[:]), nil
}

// FingerprintString parses a single SQL statement and returns its structural
// fingerprint. A parse error is returned unchanged and no fingerprint is
// produced.
func FingerprintString(s string) (string, error) {
	stmt, err := NewParser(strings.NewReader(s)).ParseStatement()
	if err != nil {
		return "", err
	}
	return Fingerprint(stmt)
}

// FingerprintStatements parses one or more SQL statements and returns one
// fingerprint per statement in source order. A parse or fingerprint error is
// returned without partial results.
func FingerprintStatements(s string) ([]string, error) {
	stmts, err := NewParser(strings.NewReader(s)).ParseStatements()
	if err != nil {
		return nil, err
	}

	fingerprints := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		fingerprint, err := Fingerprint(stmt)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints, nil
}

type fingerprintEncoder struct {
	buf []byte
}

func newFingerprintEncoder() *fingerprintEncoder {
	enc := &fingerprintEncoder{}
	enc.bytes([]byte(FingerprintVersionV1))
	return enc
}

func (enc *fingerprintEncoder) Visit(node Node) (Visitor, Node, error) {
	if err := checkFingerprintNode(node); err != nil {
		return nil, nil, err
	}

	switch node := node.(type) {
	case *Ident:
		enc.open("Ident")
		enc.string(strings.ToLower(node.Name))
		enc.close()
		return nil, node, nil

	case *NumberLit:
		enc.terminal("number")
		return nil, node, nil
	case *StringLit:
		enc.terminal("string")
		return nil, node, nil
	case *BlobLit:
		enc.terminal("blob")
		return nil, node, nil
	case *BindExpr:
		enc.terminal("bind")
		return nil, node, nil
	case *NullLit:
		enc.terminal("null")
		return nil, node, nil
	case *TimestampLit:
		enc.terminal(strings.ToUpper(node.Value))
		return nil, node, nil
	case *BoolLit:
		enc.open("bool")
		enc.uint8(0)
		enc.boolean(node.Value)
		enc.close()
		return nil, node, nil
	}

	enc.open(nodeName(node))
	if err := enc.fields(reflect.ValueOf(node)); err != nil {
		return nil, nil, err
	}
	return enc, node, nil
}

func (enc *fingerprintEncoder) VisitEnd(node Node) (Node, error) {
	enc.close()
	return node, nil
}

func (enc *fingerprintEncoder) fields(value reflect.Value) error {
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}

	structType := value.Type()
	if value.CanAddr() {
		if selectExpr, ok := value.Addr().Interface().(*SelectExpr); ok {
			enc.string("SelectStatement")
			return enc.fieldValue(reflect.ValueOf(selectExpr.SelectStatement))
		}
	}
	if selectExpr, ok := value.Interface().(SelectExpr); ok {
		enc.string("SelectStatement")
		return enc.fieldValue(reflect.ValueOf(selectExpr.SelectStatement))
	}

	for i := 0; i < value.NumField(); i++ {
		fieldType := structType.Field(i)
		field := value.Field(i)
		if !field.CanInterface() {
			continue
		}
		enc.string(fieldType.Name)
		if err := enc.fieldValue(field); err != nil {
			return fmt.Errorf("%s.%s: %w", structType.Name(), fieldType.Name, err)
		}
	}
	return nil
}

func (enc *fingerprintEncoder) fieldValue(field reflect.Value) error {
	switch value := field.Interface().(type) {
	case Pos:
		enc.boolean(value.IsValid())
		return nil
	case Token:
		enc.string(value.String())
		return nil
	}

	switch field.Kind() {
	case reflect.Bool:
		enc.boolean(field.Bool())

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		enc.varint(field.Int())

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		enc.uint(field.Uint())

	case reflect.String:
		return fmt.Errorf("%w: string field is not canonicalized", ErrUnsupportedFingerprintNode)

	case reflect.Interface:
		if field.IsNil() {
			enc.uint8(0)
			return nil
		}
		if _, ok := field.Interface().(Node); ok {
			enc.uint8(1)
			return nil
		}
		return fmt.Errorf("%w: unsupported interface %s", ErrUnsupportedFingerprintNode, field.Type())

	case reflect.Ptr:
		if field.IsNil() {
			enc.uint8(0)
			return nil
		}
		if _, ok := field.Interface().(Node); ok {
			enc.uint8(1)
			return nil
		}
		if field.Type() == reflect.TypeOf(&Pos{}) {
			enc.boolean(field.Elem().Interface().(Pos).IsValid())
			return nil
		}
		return enc.fieldValue(field.Elem())

	case reflect.Struct:
		if value, ok := field.Interface().(Pos); ok {
			enc.boolean(value.IsValid())
			return nil
		}
		if field.CanAddr() {
			if value, ok := field.Addr().Interface().(Node); ok {
				if err := checkFingerprintNode(value); err != nil {
					return err
				}
				enc.uint8(1)
				return nil
			}
		}
		return fmt.Errorf("%w: unsupported struct %s", ErrUnsupportedFingerprintNode, field.Type())

	case reflect.Slice, reflect.Array:
		enc.uint(uint64(field.Len()))

	default:
		return fmt.Errorf("%w: unsupported field type %s", ErrUnsupportedFingerprintNode, field.Type())
	}

	return nil
}

func (enc *fingerprintEncoder) open(name string) {
	enc.uint8('(')
	enc.string(name)
}

func (enc *fingerprintEncoder) close() {
	enc.uint8(')')
}

func (enc *fingerprintEncoder) terminal(name string) {
	enc.open(name)
	enc.uint8(0)
	enc.close()
}

func (enc *fingerprintEncoder) string(value string) {
	enc.bytes([]byte(value))
}

func (enc *fingerprintEncoder) bytes(value []byte) {
	enc.uint(uint64(len(value)))
	enc.buf = append(enc.buf, value...)
}

func (enc *fingerprintEncoder) boolean(value bool) {
	if value {
		enc.uint8(1)
		return
	}
	enc.uint8(0)
}

func (enc *fingerprintEncoder) varint(value int64) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutVarint(buf[:], value)
	enc.buf = append(enc.buf, buf[:n]...)
}

func (enc *fingerprintEncoder) uint(value uint64) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], value)
	enc.buf = append(enc.buf, buf[:n]...)
}

func (enc *fingerprintEncoder) uint8(value byte) {
	enc.buf = append(enc.buf, value)
}

func nodeName(node Node) string {
	nodeType := reflect.TypeOf(node)
	if nodeType.Kind() == reflect.Ptr {
		return nodeType.Elem().Name()
	}
	return nodeType.Name()
}

func checkFingerprintNode(node Node) error {
	switch node.(type) {
	case *AlterTableStatement,
		*AnalyzeStatement,
		*Assignment,
		*BeginStatement,
		*BinaryExpr,
		*BindExpr,
		*BlobLit,
		*BoolLit,
		*Call,
		*CaseBlock,
		*CaseExpr,
		*CastExpr,
		*CheckConstraint,
		*CollateConstraint,
		*CollateExpr,
		*CollationClause,
		*ColumnDefinition,
		*CommitStatement,
		*CreateIndexStatement,
		*CreateTableStatement,
		*CreateTriggerStatement,
		*CreateViewStatement,
		*CreateVirtualTableStatement,
		*CTE,
		*DefaultConstraint,
		*DeleteStatement,
		*DropIndexStatement,
		*DropTableStatement,
		*DropTriggerStatement,
		*DropViewStatement,
		*Exists,
		*ExplainStatement,
		*ExprList,
		*FilterClause,
		*ForeignKeyArg,
		*ForeignKeyConstraint,
		*FrameSpec,
		*GeneratedConstraint,
		*Ident,
		*IndexedColumn,
		*InsertStatement,
		*JoinClause,
		*JoinOperator,
		*ModuleArgument,
		*NotNullConstraint,
		*Null,
		*NullLit,
		*NumberLit,
		*OnConstraint,
		*OrderingTerm,
		*OverClause,
		*ParenExpr,
		*ParenSource,
		*PragmaStatement,
		*PrimaryKeyConstraint,
		*QualifiedRef,
		*QualifiedTableName,
		*QualifiedTableFunctionName,
		*Raise,
		*Range,
		*ReindexStatement,
		*ReleaseStatement,
		*ResultColumn,
		*ReturningClause,
		*RollbackStatement,
		*SavepointStatement,
		*SelectStatement,
		SelectExpr,
		*StringLit,
		*TimestampLit,
		*Type,
		*UnaryExpr,
		*UniqueConstraint,
		*UpdateStatement,
		*UpsertClause,
		*UsingConstraint,
		*Window,
		*WindowDefinition,
		*WithClause:
		return nil
	default:
		return fmt.Errorf("%w: %T; add encoding support before using %s", ErrUnsupportedFingerprintNode, node, FingerprintVersionV1)
	}
}
