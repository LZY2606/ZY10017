package sql

import "reflect"

// A Visitor's Visit method is invoked for each node encountered by Walk.
// If the result visitor w is not nil, Walk visits each of the children
// of node with visitor w, followed by a call of w.VisitEnd(n).
type Visitor interface {
	Visit(n Node) (w Visitor, node Node, err error)
	VisitEnd(n Node) (Node, error)
}

// Walk traverses an AST in depth-first order: It starts by calling
// v.Visit(node); node must not be nil. If the visitor w returned by
// v.Visit(node) is not nil, Walk is invoked recursively with visitor
// w for each of the non-nil children of node, followed by a call of
// w.VisitEnd(n).
func Walk(v Visitor, n Node) (Node, error) {
	return walk(v, reflect.ValueOf(n))
}

func walk(v Visitor, value reflect.Value) (Node, error) {
	node, ok := nodeFromValue(value)
	if !ok || node == nil {
		return nil, nil
	}

	next, retNode, err := v.Visit(node)
	if err != nil || next == nil {
		return retNode, err
	}

	retValue := reflect.ValueOf(retNode)
	if err := walkChildren(next, retValue); err != nil {
		return nil, err
	}
	return next.VisitEnd(retNode)
}

func walkChildren(v Visitor, value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}

	switch value.Kind() {
	case reflect.Interface, reflect.Ptr:
		if value.IsNil() {
			return nil
		}
		if value.Kind() == reflect.Ptr && value.Elem().Kind() != reflect.Struct {
			return nil
		}
		if isPosValue(value) {
			return nil
		}
		return walkChildren(v, value.Elem())

	case reflect.Struct:
		if value, ok := value.Interface().(Pos); ok && value.IsValid() {
			return nil
		}

		structType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			if err := walkField(v, value.Field(i), structType.Field(i)); err != nil {
				return err
			}
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			element := value.Index(i)
			if _, ok := nodeFromValue(element); ok {
				if _, err := walk(v, element); err != nil {
					return err
				}
			} else if err := walkChildren(v, element); err != nil {
				return err
			}
		}
	}

	return nil
}

func walkField(v Visitor, field reflect.Value, fieldType reflect.StructField) error {
	if !field.CanInterface() || fieldType.Type == reflect.TypeOf(Pos{}) || fieldType.Type == reflect.TypeOf(Token(0)) {
		return nil
	}

	switch field.Kind() {
	case reflect.Interface, reflect.Ptr:
		if field.IsNil() {
			return nil
		}
		if _, ok := field.Interface().(Node); ok {
			retNode, err := walk(v, field)
			if err != nil {
				return err
			}
			return assignWalkedNode(field, retNode)
		}
		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct && !isPosValue(field) {
			return walkChildren(v, field)
		}

	case reflect.Struct:
		if _, ok := field.Addr().Interface().(Node); ok {
			retNode, err := walk(v, field)
			if err != nil {
				return err
			}
			return assignWalkedNode(field, retNode)
		}
		return walkChildren(v, field)

	case reflect.Slice, reflect.Array:
		for i := 0; i < field.Len(); i++ {
			element := field.Index(i)
			if nodeValue, ok := nodeFromValue(element); ok && nodeValue != nil {
				retNode, err := walk(v, element)
				if err != nil {
					return err
				}
				if err := assignWalkedNode(element, retNode); err != nil {
					return err
				}
				continue
			}
			if err := walkChildren(v, element); err != nil {
				return err
			}
		}
	}

	return nil
}

func nodeFromValue(value reflect.Value) (Node, bool) {
	if !value.IsValid() {
		return nil, false
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, false
		}
		node, ok := value.Interface().(Node)
		return node, ok
	}

	if value.Kind() == reflect.Ptr && value.IsNil() {
		return nil, false
	}
	if value.CanAddr() {
		if node, ok := value.Addr().Interface().(Node); ok {
			return node, true
		}
	}
	if node, ok := value.Interface().(Node); ok {
		return node, true
	}
	return nil, false
}

func isPosValue(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	if value.Kind() == reflect.Ptr && value.Type() == reflect.TypeOf(&Pos{}) {
		return true
	}
	_, ok := value.Interface().(Pos)
	return ok
}

func assignWalkedNode(target reflect.Value, node Node) error {
	if node == nil || !target.CanSet() {
		return nil
	}

	nodeValue := reflect.ValueOf(node)
	if !nodeValue.Type().AssignableTo(target.Type()) {
		return nil
	}
	if reflect.DeepEqual(target.Interface(), node) {
		return nil
	}
	target.Set(nodeValue)
	return nil
}

// VisitFunc represents a function type that implements Visitor.
// Executes on node entry.
type VisitFunc func(Node) (Node, error)

// Visit executes fn. Walk visits node children if fn returns non-nil Visitor.
func (fn VisitFunc) Visit(node Node) (Visitor, Node, error) {
	if rn, err := fn(node); err != nil {
		return nil, nil, err
	} else {
		return fn, rn, nil
	}
}

// VisitEnd returns the node unmodified.
func (fn VisitFunc) VisitEnd(node Node) (Node, error) {
	return node, nil
}

// VisitEndFunc represents a function type that implements Visitor.
// Executes on node exit.
type VisitEndFunc func(Node) (Node, error)

// Visit returns the visitor itself to continue traversal.
func (fn VisitEndFunc) Visit(node Node) (Visitor, Node, error) {
	return fn, node, nil
}

// VisitEnd executes fn.
func (fn VisitEndFunc) VisitEnd(node Node) (Node, error) {
	return fn(node)
}
