// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path"
	"strings"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type bfsState struct {
	// edge is the callgraph edge leading to the next node in a path to an
	// interesting function.
	edge *callgraph.Edge
}

// next returns the next node in the path to an interesting function.
func (b bfsState) next() *callgraph.Node {
	if b.edge == nil {
		return nil
	}
	return b.edge.Callee
}

type nodeset map[*callgraph.Node]struct{}
type nodesetPerCapability map[cpb.Capability]nodeset

func (nc nodesetPerCapability) add(cap cpb.Capability, node *callgraph.Node) {
	m := nc[cap]
	if m == nil {
		m = make(nodeset)
		nc[cap] = m
	}
	m[node] = struct{}{}
}

// byFunction is a slice of *callgraph.Node that can be sorted using sort.Sort.
// The ordering is first by package name, then function name.
type byFunction []*callgraph.Node

func (s byFunction) Len() int { return len(s) }
func (s byFunction) Less(i, j int) bool {
	return nodeCompare(s[i], s[j]) < 0
}
func (s byFunction) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// byCaller is a slice of *callgraph.Edge that can be sorted using
// sort.Sort.  It sorts by calling function, then callsite position.
type byCaller []*callgraph.Edge

func (s byCaller) Len() int { return len(s) }
func (s byCaller) Less(i, j int) bool {
	if c := nodeCompare(s[i].Caller, s[j].Caller); c != 0 {
		return c < 0
	}
	return positionLess(callsitePosition(s[i]), callsitePosition(s[j]))
}
func (s byCaller) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func nodeCompare(a, b *callgraph.Node) int {
	return funcCompare(a.Func, b.Func)
}

// funcCompare orders by package path, then by whether the function is a
// method, then by name.  Returns {-1, 0, +1} in the manner of strings.Compare.
func funcCompare(a, b *ssa.Function) int {
	// Put nils last.
	if a == nil && b == nil {
		return 0
	} else if b == nil {
		return -1
	} else if a == nil {
		return +1
	}
	if c := strings.Compare(packagePath(a), packagePath(b)); c != 0 {
		return c
	}
	hasReceiver := func(f *ssa.Function) bool {
		sig := f.Signature
		return sig != nil && sig.Recv() != nil
	}
	if ar, br := hasReceiver(a), hasReceiver(b); !ar && br {
		return -1
	} else if ar && !br {
		return +1
	}
	return strings.Compare(a.String(), b.String())
}

// positionLess implements an ordering on token.Position.
// It orders first by filename, then by position in the file.
// Invalid positions are sorted last.
func positionLess(p1, p2 token.Position) bool {
	if p2.Line == 0 {
		// A token.Position with Line == 0 is invalid.
		return p1.Line != 0
	}
	if p1.Line == 0 {
		return false
	}
	if p1.Filename != p2.Filename {
		// Note that two positions from the same function can have different
		// filenames because the ssa.Function for "init" can include
		// initialization code for package-level variables in multiple files.
		return p1.Filename < p2.Filename
	}
	return p1.Offset < p2.Offset
}

// packagePath returns the name of the package the function belongs to, or
// "" if it has no package.
func packagePath(f *ssa.Function) string {
	// If f is an instantiation of a generic function, use its origin.
	if f.Origin() != nil {
		f = f.Origin()
	}
	if ssaPackage := f.Package(); ssaPackage != nil {
		if typesPackage := ssaPackage.Pkg; typesPackage != nil {
			return typesPackage.Path()
		}
	}
	// Check f.Object() for a package.  This covers the case of synthetic wrapper
	// functions for promoted methods of embedded fields.
	if obj := types.Object(f.Object()); obj != nil {
		if typesPackage := obj.Pkg(); typesPackage != nil {
			return typesPackage.Path()
		}
	}
	return ""
}

// callsitePosition returns a token.Position for the edge's callsite.
// If edge is nil, or the source is unavailable, the returned token.Position
// will have token.IsValid() == false.
func callsitePosition(edge *callgraph.Edge) token.Position {
	if edge == nil {
		return token.Position{}
	} else if f := edge.Caller.Func; f == nil {
		return token.Position{}
	} else if prog := f.Prog; prog == nil {
		return token.Position{}
	} else if fset := prog.Fset; fset == nil {
		return token.Position{}
	} else {
		return fset.Position(edge.Pos())
	}
}

func isStdLib(p string) bool {
	if strings.Contains(p, ".") {
		return false
	}
	return true
}

func buildGraph(pkgs []*packages.Package, populateSyntax bool) (*callgraph.Graph, *ssa.Program, map[*ssa.Function]bool) {
	rewriteCallsToSort(pkgs)
	rewriteCallsToOnceDoEtc(pkgs)
	ssaBuilderMode := ssa.InstantiateGenerics
	if populateSyntax {
		// Debug mode makes ssa.Function.Syntax() point to the ast Node for the
		// function.  This will allow us to link nodes in the callgraph with
		// functions in the syntax tree which convert unsafe.Pointer objects or
		// use the reflect package in notable ways.
		ssaBuilderMode |= ssa.GlobalDebug
	}
	ssaProg, _ := ssautil.AllPackages(pkgs, ssaBuilderMode)
	ssaProg.Build()
	graph := cha.CallGraph(ssaProg)
	allFunctions := ssautil.AllFunctions(ssaProg)
	graph = vta.CallGraph(allFunctions, graph)
	return graph, ssaProg, allFunctions
}

// functionsToRewrite lists the functions and methods like (*sync.Once).Do that
// rewriteCallsToOnceDoEtc will rewrite to calls to their arguments.
var functionsToRewrite = []matcher{
	&methodMatcher{
		pkg:                         "sync",
		typeName:                    "Once",
		methodName:                  "Do",
		functionTypedParameterIndex: 0,
	},
	&packageFunctionMatcher{
		pkg:                         "sort",
		functionName:                "Slice",
		functionTypedParameterIndex: 1,
	},
	&packageFunctionMatcher{
		pkg:                         "sort",
		functionName:                "SliceStable",
		functionTypedParameterIndex: 1,
	},
}

type matcher interface {
	// match checks if a CallExpr is a call to a particular function or method
	// that this object is looking for.  If it matches, it returns a particular
	// argument in the call that has a function type.  Otherwise it returns nil.
	match(*types.Info, *ast.CallExpr) ast.Expr
}

// packageFunctionMatcher objects match a package-scope function.
type packageFunctionMatcher struct {
	pkg                         string
	functionName                string
	functionTypedParameterIndex int
}

// methodMatcher objects match a method of some type.
type methodMatcher struct {
	pkg                         string
	typeName                    string
	methodName                  string
	functionTypedParameterIndex int
}

func (m *packageFunctionMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// The function to be called is not a selection, so it can't be a call to
		// the relevant package.  (Unless the user has dot-imported the package,
		// but we don't need to worry much about false negatives in unusual cases
		// here.)
		return nil
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand side of the selection is not a plain identifier.
		return nil
	}
	pkgName, ok := typeInfo.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return nil
	}
	if pkgName.Imported().Path() != m.pkg {
		// Not the right package.
		return nil
	}
	if name := callee.Sel.Name; name != m.functionName {
		// This isn't the function we're looking for.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The function call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// mayHaveSideEffects determines whether an expression might write to a
// variable or call a function.  It can have false positives.  It does not
// consider panicking to be a side effect, so e.g. index expressions do not
// have side effects unless one of its components do.
//
// This is used to determine whether we can delete the expression from the
// syntax tree in isCallToOnceDoEtc.
func mayHaveSideEffects(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident, *ast.BasicLit:
		return false
	case nil:
		return false // we can reach a nil via *ast.SliceExpr
	case *ast.FuncLit:
		return false // a definition doesn't do anything on its own
	case *ast.CallExpr:
		return true
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if mayHaveSideEffects(elt) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return mayHaveSideEffects(e.X)
	case *ast.SelectorExpr:
		return mayHaveSideEffects(e.X)
	case *ast.IndexExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Index)
	case *ast.IndexListExpr:
		for _, idx := range e.Indices {
			if mayHaveSideEffects(idx) {
				return true
			}
		}
		return mayHaveSideEffects(e.X)
	case *ast.SliceExpr:
		return mayHaveSideEffects(e.X) ||
			mayHaveSideEffects(e.Low) ||
			mayHaveSideEffects(e.High) ||
			mayHaveSideEffects(e.Max)
	case *ast.TypeAssertExpr:
		return mayHaveSideEffects(e.X)
	case *ast.StarExpr:
		return mayHaveSideEffects(e.X)
	case *ast.UnaryExpr:
		return mayHaveSideEffects(e.X)
	case *ast.BinaryExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Y)
	case *ast.KeyValueExpr:
		return mayHaveSideEffects(e.Key) || mayHaveSideEffects(e.Value)
	}
	return true
}

func (m *methodMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if mayHaveSideEffects(sel.X) {
		// The expression may be something like foo().Do(bar), which we can't
		// rewrite to a call to bar because then the analysis would not see the
		// call to foo.
		return nil
	}
	calleeType := typeInfo.TypeOf(sel.X)
	if calleeType == nil {
		return nil
	}
	if ptr, ok := calleeType.(*types.Pointer); ok {
		calleeType = ptr.Elem()
	}
	named, ok := calleeType.(*types.Named)
	if !ok {
		return nil
	}
	if named.Obj().Pkg() != nil {
		if pkg := named.Obj().Pkg().Path(); pkg != m.pkg {
			// Not the right package.
			return nil
		}
	}
	if named.Obj().Name() != m.typeName {
		// Not the right type.
		return nil
	}
	if name := sel.Sel.Name; name != m.methodName {
		// Not the right method.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The method call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// visitor is passed to ast.Visit, to find AST nodes where
// unsafe.Pointer values are converted to pointers.
// It satisfies the ast.Visitor interface.
type visitor struct {
	// The sets we are populating.
	unsafeFunctionNodes map[ast.Node]struct{}
	// Set to true if an unsafe.Pointer conversion is found that is not inside
	// a function, method, or function literal definition.
	seenUnsafePointerUseInInitialization *bool
	// The Package for the ast Node being visited.  This is used to get type
	// information.
	pkg *packages.Package
	// The node for the current function being visited.  When function definitions
	// are nested, this is the innermost function.
	currentFunction ast.Node // *ast.FuncDecl or *ast.FuncLit
}

// containsReflectValue returns true if t is reflect.Value, or is a struct
// or array containing reflect.Value.
func containsReflectValue(t types.Type) bool {
	seen := map[types.Type]struct{}{}
	var rec func(t types.Type) bool
	rec = func(t types.Type) bool {
		if t == nil {
			return false
		}
		if t.String() == "reflect.Value" {
			return true
		}
		// avoid an infinite loop if the type is recursive somehow.
		if _, ok := seen[t]; ok {
			return false
		}
		seen[t] = struct{}{}
		// If the underlying type is different, use that.
		if u := t.Underlying(); !types.Identical(t, u) {
			return rec(u)
		}
		// Check fields of structs.
		if s, ok := t.(*types.Struct); ok {
			for i := 0; i < s.NumFields(); i++ {
				if rec(s.Field(i).Type()) {
					return true
				}
			}
		}
		// Check elements of arrays.
		if a, ok := t.(*types.Array); ok {
			return rec(a.Elem())
		}
		return false
	}
	return rec(t)
}

func (v visitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return v // the return value is ignored if node == nil.
	}
	switch node := node.(type) {
	case *ast.FuncDecl, *ast.FuncLit:
		// The subtree at this node is a function definition or function literal.
		// The visitor returned here is used to visit this node's children, so we
		// return a visitor with the current function set to this node.
		v.currentFunction = node
		return v
	case *ast.CallExpr:
		// A type conversion is represented as a CallExpr node with a Fun that is a
		// type, and Args containing the expression to be converted.
		//
		// If this node has a single argument which is an unsafe.Pointer (or
		// is equivalent to an unsafe.Pointer) and the callee is a type which is not
		// uintptr, we add the current function to v.unsafeFunctionNodes.
		funType := v.pkg.TypesInfo.Types[node.Fun]
		if !funType.IsType() {
			// The callee is not a type; it's probably a function or method.
			break
		}
		if b, ok := funType.Type.Underlying().(*types.Basic); ok && b.Kind() == types.Uintptr {
			// The conversion is to a uintptr, not a pointer.  On its own, this is
			// safe.
			break
		}
		var args []ast.Expr = node.Args
		if len(args) != 1 {
			// There wasn't the right number of arguments.
			break
		}
		argType := v.pkg.TypesInfo.Types[args[0]].Type
		if argType == nil {
			// The argument has no type information.
			break
		}
		if b, ok := argType.Underlying().(*types.Basic); !ok || b.Kind() != types.UnsafePointer {
			// The argument's type is not equivalent to unsafe.Pointer.
			break
		}
		if v.currentFunction == nil {
			*v.seenUnsafePointerUseInInitialization = true
		} else {
			v.unsafeFunctionNodes[v.currentFunction] = struct{}{}
		}
	}
	return v
}

// forEachPackageIncludingDependencies calls fn exactly once for each package
// that is in pkgs or in the transitive dependencies of pkgs.
func forEachPackageIncludingDependencies(pkgs []*packages.Package, fn func(*packages.Package)) {
	visitedPackages := make(map[*packages.Package]struct{})
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if _, ok := visitedPackages[p]; ok {
			return
		}
		visitedPackages[p] = struct{}{}
		for _, p2 := range p.Imports {
			visit(p2)
		}
		fn(p)
	}
	for _, p := range pkgs {
		visit(p)
	}
}

func programName() string {
	if a := os.Args; len(a) >= 1 {
		return path.Base(a[0])
	}
	return "capslock"
}
