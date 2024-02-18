// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"unsafe"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

// operandMode has the same layout as types.operandMode.
type operandMode byte

const (
	noValueMode  operandMode = 1
	constantMode operandMode = 4
	valueMode    operandMode = 7
)

// constructTypeAndValue constructs a types.TypeAndValue.  These are used in
// the types.Info.Types map to store the known types of expressions, and the
// values of constant expressions.
func constructTypeAndValue(mode operandMode, t types.Type, v constant.Value) types.TypeAndValue {
	// The mode field of types.TypeAndValue is not exported, so we make our own
	// copy of the type definition, and use unsafe conversion to get the type we
	// want.
	tv := struct {
		mode  operandMode
		Types types.Type
		Value constant.Value
	}{mode, t, v}
	return *(*types.TypeAndValue)(unsafe.Pointer(&tv))
}

// typeAndValueForResults constructs a TypeAndValue corresponding to the return
// values of a function.
func typeAndValueForResults(results *types.Tuple) types.TypeAndValue {
	if results == nil {
		// Case 1: the function has no return values.
		return constructTypeAndValue(noValueMode, results, nil)
	}
	if results.Len() == 1 {
		// Case 2: the function has a single return value.
		return constructTypeAndValue(valueMode, results.At(0).Type(), nil)
	}
	// Case 3: the function returns a tuple of more than one value.
	return constructTypeAndValue(valueMode, results, nil)
}

// zeroLiteral creates and returns a zero literal of type int, and adds its
// type information to typeInfo.Types.
func zeroLiteral(typeInfo *types.Info) ast.Expr {
	expr := &ast.BasicLit{Kind: token.INT, Value: "0"}
	typeInfo.Types[expr] = constructTypeAndValue(constantMode, types.Typ[types.Int], constant.MakeInt64(0))
	return expr
}

// selectionForMethod finds the Selection object for the given method.
func selectionForMethod(typ types.Type, name string) *types.Selection {
	var ms *types.MethodSet = types.NewMethodSet(typ)
	// The package is not needed for exported methods, so we can pass nil for the
	// package parameter of Lookup.
	sel := ms.Lookup(nil, name)
	return sel
}

// rewriteCallsToSort iterates through the packages in pkgs, including all
// transitively-imported packages, and finds calls to sort.Sort, sort.Stable,
// and sort.IsSorted, which each have a sort.Interface parameter.  We replace
// each of these calls with a set of calls to each of the interface methods
// individually (Len, Less, and Swap.)  e.g., this code:
//
//	sort.Sort(xs)
//
// would be replaced with:
//
//	xs.Len()
//	xs.Less(0,0)
//	xs.Swap(0,0)
//
// This improves the precision of the callgraph the analysis produces.  The
// analysis produces a set of possible dynamic types for the sort.Interface
// value, and adds a callgraph edge to the methods for each of those.
//
// Without this change to the callgraph, we would get paths to the
// sort.Interface methods for every possible dynamic type for all the values
// passed to the same sort function anywhere in the program, which can result
// in a large number of false positives.
func rewriteCallsToSort(pkgs []*packages.Package) {
	forEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, node := range file.Decls {
				var pre astutil.ApplyFunc
				pre = func(c *astutil.Cursor) bool {
					// If the current node, c.Node(), is a call to sort.Sort (or
					// sort.Stable or sort.IsSorted), replace it with calls to
					// obj.Less, obj.Swap, and obj.Len, where obj is the argument
					// that was passed to sort.
					if _, ok := c.Node().(ast.Stmt); !ok {
						// c.Node() is not a statement.
						return true
					}
					canRewrite := false
					switch c.Parent().(type) {
					case *ast.BlockStmt, *ast.CaseClause, *ast.LabeledStmt:
						canRewrite = true
					case *ast.CommClause:
						canRewrite = c.Index() >= 0
					}
					if !canRewrite {
						// The statement is in a position in the syntax tree where it
						// can't be replaced with a block or with multiple statements, so
						// we give up.
						return true
					}

					obj := isCallToSort(p.TypesInfo, c.Node())
					if obj == nil {
						// This was not a call to a sort function.
						//
						// We always return true from this function, because the return
						// value indicates to astutil.Apply whether to keep searching.
						return true
					}
					// Less and Swap each take two integer arguments.  The values aren't
					// important for our callgraph analysis -- we do not look at values
					// to determine which way an if statement branches, for example --
					// so we just use two zeroes.
					args1 := []ast.Expr{zeroLiteral(p.TypesInfo), zeroLiteral(p.TypesInfo)}
					args2 := []ast.Expr{zeroLiteral(p.TypesInfo), zeroLiteral(p.TypesInfo)}
					// Create a block with three statements which call Less, Swap,
					// and Len.  Replace the current node with this block.
					s1 := statementCallingMethod(p.TypesInfo, obj, "Less", args1)
					s2 := statementCallingMethod(p.TypesInfo, obj, "Swap", args2)
					s3 := statementCallingMethod(p.TypesInfo, obj, "Len", nil)
					if s1 == nil || s2 == nil || s3 == nil {
						// We did not succeed in creating these statements.
						return true
					}
					c.Replace(&ast.BlockStmt{List: []ast.Stmt{s1, s2, s3}})
					return true
				}
				astutil.Apply(node, pre, nil)
			}
		}
	})
}

// rewriteCallsToOnceDoEtc is similar to rewriteCallsToSort.  It finds calls
// to some standard-library functions and methods which have a function
// parameter, and changes those calls to call the function argument directly
// instead.
//
// e.g. this code:
//
//	var myonce *sync.Once = ...
//	myonce.Do(fn)
//
// would be replaced with:
//
//	var myonce *sync.Once = ...
//	fn()
func rewriteCallsToOnceDoEtc(pkgs []*packages.Package) {
	forEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, node := range file.Decls {
				var pre astutil.ApplyFunc
				pre = func(c *astutil.Cursor) bool {
					obj := isCallToOnceDoEtc(p.TypesInfo, c.Node())
					if obj == nil {
						// This was not a call to a relevant function or method.
						return true
					}
					fnType, ok := p.TypesInfo.TypeOf(obj).(*types.Signature)
					if !ok {
						// The argument does not appear to be a function.
						return true
					}
					// Create some arguments to pass to the function.  The parameters
					// must all be integers.
					params := fnType.Params()
					args := make([]ast.Expr, params.Len())
					for i := range args {
						args[i] = zeroLiteral(p.TypesInfo)
					}
					c.Replace(
						statementCallingFunctionObject(p.TypesInfo, obj, args))
					return true
				}
				astutil.Apply(node, pre, nil)
			}
		}
	})
}

// isCallToSort checks if node is a statement calling sort.Sort, sort.Stable,
// or sort.IsSorted.  If so, it returns the argument to that function.
// Otherwise, it returns nil.
func isCallToSort(typeInfo *types.Info, node ast.Node) ast.Expr {
	expr, ok := node.(*ast.ExprStmt)
	if !ok {
		// Not a statement node.
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		// Not a function call.
		return nil
	}
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// The function to be called is not a selection, so it can't be a call to
		// the sort package.  (Unless the user has dot-imported "sort", but we
		// don't need to worry much about false negatives in unusual cases here.)
		return nil
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand-side of the selection is not a plain identifier.
		return nil
	}
	pkgName, ok := typeInfo.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return nil
	}
	if pkgName.Imported().Path() != "sort" {
		// The package isn't "sort".  (We use Imported().Path() because the import
		// name could be misleading, e.g.:
		// import (
		//   sort "os"
		// )
		return nil
	}
	if name := callee.Sel.Name; name != "Sort" && name != "Stable" && name != "IsSorted" {
		// This isn't one of the functions we're looking for.
		return nil
	}
	if len(call.Args) != 1 {
		// The function call doesn't have one argument.
		return nil
	}
	return call.Args[0]
}

// isCallToOnceDoEtc checks if node is a statement calling a function or method
// like (*sync.Once).Do.  If so, it returns the function-typed argument to that
// function.  Otherwise, it returns nil.
func isCallToOnceDoEtc(typeInfo *types.Info, node ast.Node) ast.Expr {
	expr, ok := node.(*ast.ExprStmt)
	if !ok {
		// Not a statement node.
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		// Not a call expression.
		return nil
	}
	for _, m := range functionsToRewrite {
		if e := m.match(typeInfo, call); e != nil {
			return e
		}
	}
	return nil
}

// statementCallingMethod constructs a statement that calls a method.  The
// receiver is recv, the method name is methodName, and the arguments passed
// to the call are in args.
//
// New AST structures that are created by statementCallingMethod are added
// to the Types, Selections and Uses fields of typeInfo as needed.  The
// expressions in methodName and args should already be in typeInfo.
//
// If the statement cannot be created, returns nil.
func statementCallingMethod(typeInfo *types.Info, recv ast.Expr, methodName string, args []ast.Expr) *ast.ExprStmt {
	// Construct an ast node for the method name, and add it to typeInfo.Uses.
	methodIdent := ast.NewIdent(methodName)
	var selection *types.Selection = selectionForMethod(typeInfo.TypeOf(recv), methodName)
	if selection == nil {
		// We did not find the desired method for this type.  recv might be an
		// untyped nil.
		return nil
	}
	typeInfo.Uses[methodIdent] = selection.Obj()
	// Construct an ast node for the selection (e.g. "v.M"), and add it to
	// typeInfo.Selections and typeInfo.Types.
	selectorExpr := &ast.SelectorExpr{X: recv, Sel: methodIdent}
	typeInfo.Selections[selectorExpr] = selection
	typeInfo.Types[selectorExpr] = constructTypeAndValue(valueMode, selection.Type(), nil)
	// Construct an ast node for the call (e.g. "v.M(arg1, arg2)") and add it
	// to typeInfo.Types.
	callExpr := &ast.CallExpr{Fun: selectorExpr, Args: append([]ast.Expr(nil), args...)}
	typeInfo.Types[callExpr] = typeAndValueForResults(selection.Type().(*types.Signature).Results())
	// Return an ast node for a statement which is just the call.  No type
	// information is needed for statements.
	return &ast.ExprStmt{X: callExpr}
}

// statementCallingFunctionObject constructs a statement that calls a function.
//
// New AST structures that are created by statementCallingFunctionObject are
// added to the Types fields of typeInfo as needed.  The expressions in fn and
// args should already be in typeInfo.
func statementCallingFunctionObject(typeInfo *types.Info, fn ast.Expr, args []ast.Expr) *ast.ExprStmt {
	// Construct an ast node for the call and add it to typeInfo.Types.
	callExpr := &ast.CallExpr{Fun: fn, Args: append([]ast.Expr(nil), args...)}
	fnType := typeInfo.TypeOf(fn)
	fnTypeSignature, _ := fnType.(*types.Signature)
	if fnTypeSignature == nil {
		panic(fmt.Sprintf("cannot get type signature of function %v", fn))
	}
	typeInfo.Types[callExpr] = typeAndValueForResults(fnTypeSignature.Results())
	// Return an ast node for a statement which is just the call.  No type
	// information is needed for statements.
	return &ast.ExprStmt{X: callExpr}
}
