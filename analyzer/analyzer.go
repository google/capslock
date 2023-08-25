// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"fmt"
	"go/ast"
	"go/types"
	"log"
	"path"
	"sort"
	"strings"

	"github.com/google/capslock/interesting"
	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"google.golang.org/protobuf/proto"
)

// GetClassifier returns a classifier for mapping packages and functions to the
// appropriate capability.
// If excludedUnanalyzed is true, the UNANALYZED capability is never returned.
func GetClassifier(excludeUnanalyzed bool) *interesting.Classifier {
	classifier := interesting.DefaultClassifier()
	if excludeUnanalyzed {
		return interesting.ClassifierExcludingUnanalyzed(classifier)
	}
	return classifier
}

// GetCapabilityInfo analyzes the packages in pkgs.  For each function in those
// packages which have a path in the callgraph to an "interesting" function
// (see the "interesting" package), we log details of the capability usage.
//
// One CapabilityInfo is returned for every (function, capability) pair, with
// one example path in the callgraph that demonstrates that capability.
func GetCapabilityInfo(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier) *cpb.CapabilityInfoList {
	var caps []*cpb.CapabilityInfo
	forEachPath(pkgs, queriedPackages,
		func(cap cpb.Capability, nodes map[*callgraph.Node]bfsState,
			v *callgraph.Node) {
			i := 0
			c := cpb.CapabilityInfo{}
			var n string
			var ctype cpb.CapabilityType
			var b strings.Builder
			var incomingEdge *callgraph.Edge
			for v != nil {
				s := v.Func.String()
				fn := &cpb.Function{Name: proto.String(s)}
				if position := callsitePosition(incomingEdge); position.IsValid() {
					fn.Site = &cpb.Function_Site{
						Filename: proto.String(path.Base(position.Filename)),
						Line:     proto.Int64(int64(position.Line)),
						Column:   proto.Int64(int64(position.Column)),
					}
				}
				c.Path = append(c.Path, fn)
				if i == 0 {
					n = v.Func.Package().Pkg.Path()
					ctype = cpb.CapabilityType_CAPABILITY_TYPE_DIRECT
					fmt.Fprintf(&b, "%s", s)
					c.Capability = cap.Enum()
					c.PackageDir = proto.String(v.Func.Package().Pkg.Path())
					c.PackageName = proto.String(v.Func.Package().Pkg.Name())
				} else {
					fmt.Fprintf(&b, " %s", s)
				}
				i++
				if pName := packagePath(v.Func); n != pName && !isStdLib(pName) {
					ctype = cpb.CapabilityType_CAPABILITY_TYPE_TRANSITIVE
				}
				incomingEdge, v = nodes[v].edge, nodes[v].next()
			}
			c.CapabilityType = &ctype
			c.DepPath = proto.String(b.String())
			caps = append(caps, &c)
		}, classifier)
	return &cpb.CapabilityInfoList{
		CapabilityInfo: caps,
		ModuleInfo:     collectModuleInfo(pkgs),
		PackageInfo:    collectPackageInfo(pkgs),
	}
}

type CapabilityCounter struct {
	capability       cpb.Capability
	count            int64
	direct_count     int64
	transitive_count int64
	example          string
}

// GetCapabilityStats analyzes the packages in pkgs.  For each function in
// those packages which have a path in the callgraph to an "interesting"
// function (see the "interesting" package), we give aggregated statistics
// about the capability usage.
func GetCapabilityStats(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier) *cpb.CapabilityStatList {
	var cs []*cpb.CapabilityStats
	cm := make(map[string]*CapabilityCounter)
	forEachPath(pkgs, queriedPackages,
		func(cap cpb.Capability, nodes map[*callgraph.Node]bfsState, v *callgraph.Node) {
			if _, ok := cm[cap.String()]; !ok {
				cm[cap.String()] = &CapabilityCounter{count: 1, capability: cap}
			} else {
				cm[cap.String()].count += 1
			}
			i := 0
			var b strings.Builder
			var n string
			isDirect := true
			for v != nil {
				s := v.Func.String()
				if i == 0 {
					n = v.Func.Package().Pkg.Path()
					fmt.Fprintf(&b, "%s", s)
				} else {
					fmt.Fprintf(&b, " %s", s)
				}
				i++
				if pName := packagePath(v.Func); n != pName && !isStdLib(pName) {
					isDirect = false
				}
				v = nodes[v].next()
			}
			if isDirect {
				if _, ok := cm[cap.String()]; !ok {
					cm[cap.String()] = &CapabilityCounter{count: 1, direct_count: 1}
				} else {
					cm[cap.String()].direct_count += 1
				}
			} else {
				if _, ok := cm[cap.String()]; !ok {
					cm[cap.String()] = &CapabilityCounter{count: 1, transitive_count: 1}
				} else {
					cm[cap.String()].transitive_count += 1
				}
			}
			if _, ok := cm[cap.String()]; !ok {
				cm[cap.String()] = &CapabilityCounter{example: b.String()}
			} else {
				cm[cap.String()].example = b.String()
			}
		}, classifier)
	for _, counts := range cm {
		cs = append(cs, &cpb.CapabilityStats{
			Capability:      &counts.capability,
			Count:           &counts.count,
			DirectCount:     &counts.direct_count,
			TransitiveCount: &counts.transitive_count,
			ExampleCallpath: &counts.example})
	}
	return &cpb.CapabilityStatList{
		CapabilityStats: cs,
		ModuleInfo:      collectModuleInfo(pkgs),
	}
}

// GetCapabilityCount analyzes the packages in pkgs.  For each function in
// those packages which have a path in the callgraph to an "interesting"
// function (see the "interesting" package), we give an aggregate count of the
// capability usage.
func GetCapabilityCounts(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier) *cpb.CapabilityCountList {
	cm := make(map[string]int64)
	forEachPath(pkgs, queriedPackages,
		func(cap cpb.Capability, nodes map[*callgraph.Node]bfsState, v *callgraph.Node) {
			if _, ok := cm[cap.String()]; !ok {
				cm[cap.String()] = 1
			} else {
				cm[cap.String()] += 1
			}
		}, classifier)
	return &cpb.CapabilityCountList{
		CapabilityCounts: cm,
		ModuleInfo:       collectModuleInfo(pkgs),
	}
}

// searchBackwardsFromCapabilities returns the set of all function nodes that
// have a path to a function with some capability.
func searchBackwardsFromCapabilities(nodesByCapability nodesetPerCapability, safe nodeset, classifier *interesting.Classifier) nodeset {
	var (
		visited = make(nodeset)
		q       []*callgraph.Node
	)
	// Initialize the queue to contain the nodes with a capability.
	for _, nodes := range nodesByCapability {
		for v := range nodes {
			if _, ok := safe[v]; ok {
				continue
			}
			q = append(q, v)
			visited[v] = struct{}{}
		}
	}
	// Perform a BFS backwards through the call graph from the interesting
	// nodes.
	for len(q) > 0 {
		v := q[0]
		q = q[1:]
		calleeName := v.Func.String()
		for _, edge := range v.In {
			callerName := edge.Caller.Func.String()
			if !classifier.IncludeCall(callerName, calleeName) {
				continue
			}
			w := edge.Caller
			if _, ok := safe[w]; ok {
				continue
			}
			if _, ok := visited[w]; ok {
				// We have already visited w.
				continue
			}
			visited[w] = struct{}{}
			q = append(q, w)
		}
	}
	return visited
}

// searchForwardsFromQueriedFunctions searches from a set of function nodes to
// find all the nodes they can reach which themselves reach a node with some
// capability.
//
// outputCall is called for each edge between two such nodes.
// outputCapability is called for each node reached in the graph that has some
// direct capability.
func searchForwardsFromQueriedFunctions(
	nodes nodeset,
	nodesByCapability nodesetPerCapability,
	allNodesWithExplicitCapability,
	canReachCapability nodeset,
	classifier *interesting.Classifier,
	outputCall func(from, to *callgraph.Node),
	outputCapability func(fn *callgraph.Node, c cpb.Capability)) {
	var q []*callgraph.Node
	for v := range nodes {
		q = append(q, v)
	}
	for len(q) > 0 {
		v := q[0]
		q = q[1:]
		for c, nodes := range nodesByCapability {
			if _, ok := nodes[v]; ok {
				outputCapability(v, c)
			}
		}
		if _, ok := allNodesWithExplicitCapability[v]; ok {
			continue
		}
		calleeName := v.Func.String()
		out := make(nodeset)
		for _, edge := range v.Out {
			callerName := edge.Caller.Func.String()
			if !classifier.IncludeCall(callerName, calleeName) {
				continue
			}
			w := edge.Callee
			if _, ok := canReachCapability[w]; !ok {
				continue
			}
			out[w] = struct{}{}
		}
		for w := range out {
			outputCall(v, w)
			if _, ok := nodes[w]; ok {
				// We have already visited w.
				continue
			}
			nodes[w] = struct{}{}
			q = append(q, w)
		}
	}
}

// CapabilityGraph analyzes the callgraph for the packages in pkgs.
//
// It outputs the graph containing all paths from a function belonging
// to one of the packages in queriedPackages to a function which has
// some capability.
//
// outputCall is called for each edge between two nodes.
// outputCapability is called for each node in the graph that has some
// capability.
func CapabilityGraph(pkgs []*packages.Package,
	queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier,
	outputCall func(from, to *callgraph.Node),
	outputCapability func(fn *callgraph.Node, c cpb.Capability)) {

	safe, nodesByCapability, extraNodesByCapability := getPackageNodesWithCapability(pkgs, classifier)
	nodesByCapability, allNodesWithExplicitCapability := mergeCapabilities(nodesByCapability, extraNodesByCapability)
	extraNodesByCapability = nil

	canReachCapability := searchBackwardsFromCapabilities(nodesByCapability, safe, classifier)

	canBeReachedFromQuery := make(nodeset)
	for v := range canReachCapability {
		if v.Func.Package() == nil {
			continue
		}
		if _, ok := queriedPackages[v.Func.Package().Pkg]; ok {
			canBeReachedFromQuery[v] = struct{}{}
		}
	}

	searchForwardsFromQueriedFunctions(
		canBeReachedFromQuery,
		nodesByCapability,
		allNodesWithExplicitCapability,
		canReachCapability,
		classifier,
		outputCall,
		outputCapability)
}

// getPackageNodesWithCapability analyzes all the functions in pkgs and their
// transitive dependencies, and returns three sets of callgraph nodes.
//
// safe contains the set of nodes for functions that have been explicitly
// classified as safe.
// nodesByCapability contains nodes that have been explicitly categorized
// as having some particular capability.  These are in a map from capability
// to a set of nodes.
// extraNodesByCapability contains nodes for functions that use unsafe pointers
// or the reflect package in a way that we want to report to the user.
func getPackageNodesWithCapability(pkgs []*packages.Package,
	classifier *interesting.Classifier) (safe nodeset, nodesByCapability, extraNodesByCapability nodesetPerCapability) {
	if packages.PrintErrors(pkgs) > 0 {
		log.Fatal("Some packages had errors. Aborting analysis.")
	}
	graph, ssaProg, allFunctions := buildGraph(pkgs, true)
	unsafePointerFunctions := findUnsafePointerConversions(pkgs, ssaProg)
	ssaProg = nil // possibly save memory; we don't use ssaProg again
	safe, nodesByCapability = getNodeCapabilities(graph, classifier)
	extraNodesByCapability = make(nodesetPerCapability)
	// Find functions that copy reflect.Value objects in a way that could
	// possibly cause a data race, and add their nodes to
	// extraNodesByCapability[Capability_CAPABILITY_REFLECT].
	for f := range allFunctions {
		// Find the function variables that do not escape.
		locals := map[ssa.Value]struct{}{}
		for _, l := range f.Locals {
			if !l.Heap {
				locals[l] = struct{}{}
			}
		}
		for _, b := range f.Blocks {
			for _, i := range b.Instrs {
				// An IndexAddr instruction creates an SSA value which refers to an
				// element of an array.  An element of a local array is also local.
				if ia, ok := i.(*ssa.IndexAddr); ok {
					if _, islocal := locals[ia.X]; islocal {
						locals[ia] = struct{}{}
					}
				}
				// A FieldAddr instruction creates an SSA value which refers to a
				// field of a struct.  A field of a local struct is also local.
				if f, ok := i.(*ssa.FieldAddr); ok {
					if _, islocal := locals[f.X]; islocal {
						locals[f] = struct{}{}
					}
				}
				// Check the destination of store instructions.
				if s, ok := i.(*ssa.Store); ok {
					dest := s.Addr
					if _, islocal := locals[dest]; islocal {
						continue
					}
					// dest.Type should be a types.Pointer pointing to the type of the
					// value that is copied by this instruction.
					typ, ok := dest.Type().(*types.Pointer)
					if !ok {
						continue
					}
					if !containsReflectValue(typ.Elem()) {
						continue
					}
					if node, ok := graph.Nodes[f]; ok {
						// This is a store to a non-local reflect.Value, or to a non-local
						// object that contains a reflect.Value.
						extraNodesByCapability.add(cpb.Capability_CAPABILITY_REFLECT, node)
					}
				}
			}
		}
	}
	// Add nodes for the functions in unsafePointerFunctions to
	// extraNodesByCapability[Capability_CAPABILITY_UNSAFE_POINTER].
	for f := range unsafePointerFunctions {
		if node, ok := graph.Nodes[f]; ok {
			extraNodesByCapability.add(cpb.Capability_CAPABILITY_UNSAFE_POINTER, node)
		}
	}
	// Add the arbitrary-execution capability to asm function nodes.
	for f, node := range graph.Nodes {
		if f.Blocks == nil {
			// No source code for this function.
			if f.Synthetic != "" {
				// Exclude synthetic functions, such as those loaded from object files.
				continue
			}
			extraNodesByCapability.add(cpb.Capability_CAPABILITY_ARBITRARY_EXECUTION, node)
		}
	}
	return safe, nodesByCapability, extraNodesByCapability
}

// findUnsafePointerConversions uses analysis of the syntax tree to find
// functions which convert unsafe.Pointer values to another type.
func findUnsafePointerConversions(pkgs []*packages.Package, ssaProg *ssa.Program) (unsafePointer map[*ssa.Function]struct{}) {
	// AST nodes corresponding to functions which convert unsafe.Pointer values.
	unsafeFunctionNodes := make(map[ast.Node]struct{})
	// Packages which contain variables that are initialized using
	// unsafe.Pointer conversions.  We will later find the function nodes
	// corresponding to the init functions for these packages.
	packagesWithUnsafePointerUseInInitialization := make(map[*types.Package]struct{})
	forEachPackageIncludingDependencies(pkgs, func(pkg *packages.Package) {
		seenUnsafePointerUseInInitialization := false
		for _, file := range pkg.Syntax {
			vis := visitor{
				unsafeFunctionNodes:                  unsafeFunctionNodes,
				seenUnsafePointerUseInInitialization: &seenUnsafePointerUseInInitialization,
				pkg:                                  pkg,
			}
			ast.Walk(vis, file)
		}
		if seenUnsafePointerUseInInitialization {
			// One of the files in this package contained an unsafe.Pointer
			// conversion in the initialization expression for a package-scoped
			// variable.
			// We want to find later the *ssa.Package object corresponding to the
			// *packages.Package object we have now.  There is no direct pointer
			// between the two, but each has a pointer to the corresponding
			// *types.Package object, so we store that here.
			packagesWithUnsafePointerUseInInitialization[pkg.Types] = struct{}{}
		}
	})
	// Find the *ssa.Function pointers corresponding to the syntax nodes found
	// above.
	unsafePointerFunctions := make(map[*ssa.Function]struct{})
	var processFunction func(f *ssa.Function)
	processFunction = func(f *ssa.Function) {
		if _, ok := unsafeFunctionNodes[f.Syntax()]; ok {
			unsafePointerFunctions[f] = struct{}{}
		}
		// Process child functions, e.g. function literals contained inside f.
		for _, fn := range f.AnonFuncs {
			processFunction(fn)
		}
	}
	for _, pkg := range ssaProg.AllPackages() {
		_, initUsesUnsafePointer := packagesWithUnsafePointerUseInInitialization[pkg.Pkg]
		// pkg.Members contains all "top-level" functions; other functions are
		// reached recursively through those.
		for _, m := range pkg.Members {
			if f, ok := m.(*ssa.Function); ok {
				if initUsesUnsafePointer && f.Name() == "init" {
					// This package had an unsafe.Pointer conversion in the initialization
					// expression for a package-scoped variable.  f is the "init" function
					// for the package, so we add it to unsafePointerFunctions.
					// There will always be an init function for each package; if one
					// didn't exist in the source, a synthetic one will have been
					// created.
					unsafePointerFunctions[f] = struct{}{}
				}
				processFunction(f)
			}
		}
	}
	return unsafePointerFunctions
}

func getNodeCapabilities(graph *callgraph.Graph,
	classifier *interesting.Classifier) (safe nodeset, nodesByCapability nodesetPerCapability) {
	safe = make(nodeset)
	nodesByCapability = make(nodesetPerCapability)
	for _, v := range graph.Nodes {
		if v.Func == nil {
			continue
		}
		var c cpb.Capability
		if v.Func.Package() != nil && v.Func.Package().Pkg != nil {
			// Categorize v.Func.
			pkg := v.Func.Package().Pkg.Path()
			name := v.Func.String()
			c = classifier.FunctionCategory(pkg, name)
		} else {
			origin := v.Func.Origin()
			if origin == nil || origin.Package() == nil || origin.Package().Pkg == nil {
				continue
			}
			// v.Func is an instantiation of a generic function.  Get the package
			// name and function name of the generic function, and categorize that
			// instead.
			pkg := origin.Package().Pkg.Path()
			name := origin.String()
			c = classifier.FunctionCategory(pkg, name)
		}
		if c == cpb.Capability_CAPABILITY_SAFE {
			safe[v] = struct{}{}
		} else if c != cpb.Capability_CAPABILITY_UNSPECIFIED {
			nodesByCapability.add(c, v)
		}
	}
	return safe, nodesByCapability
}

func mergeCapabilities(nodesByCapability, extraNodesByCapability nodesetPerCapability) (nodesetPerCapability, nodeset) {
	// We gather here all the nodes which were given an explicit categorization.
	// We will not search for paths that go through these nodes to reach other
	// capabilities; for example, we do not report that os.ReadFile also has
	// a descendant that will make system calls.
	allNodesWithExplicitCapability := make(nodeset)
	for _, nodes := range nodesByCapability {
		for v := range nodes {
			allNodesWithExplicitCapability[v] = struct{}{}
		}
	}
	// Now that we have constructed allNodesWithExplicitCapability, we add the
	// nodes from extraNodesByCapability to nodesByCapability, so that we find
	// paths to all these nodes together when we do a BFS.
	// extraNodesByCapability contains function capabilities that our analyzer
	// found by examining the function's source code.  These findings are
	// ignored when they apply to a function that already has an explicit
	// category.
	for cap, ns := range extraNodesByCapability {
		for node := range ns {
			if _, ok := allNodesWithExplicitCapability[node]; ok {
				// This function already has an explicit category; don't add this
				// extra capability.
				continue
			}
			nodesByCapability.add(cap, node)
		}
	}
	return nodesByCapability, allNodesWithExplicitCapability
}

// forEachPath analyzes the callgraph rooted at the packages in pkgs.
//
// For each capability, a BFS is run to find all functions in queriedPackages
// which have a path in the callgraph to a function with that capability.
//
// fn is called for each of these (capability, function) pairs.  fn is passed
// the capability, a map describing the current state of the BFS, and the node
// in the callgraph representing the function.  fn can use this information
// to reconstruct the path.
//
// forEachPath may modify pkgs.
func forEachPath(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	fn func(cpb.Capability, map[*callgraph.Node]bfsState, *callgraph.Node), classifier *interesting.Classifier) {
	safe, nodesByCapability, extraNodesByCapability := getPackageNodesWithCapability(pkgs, classifier)
	nodesByCapability, allNodesWithExplicitCapability := mergeCapabilities(nodesByCapability, extraNodesByCapability)
	extraNodesByCapability = nil // we don't use extraNodesByCapability again.
	for cap, nodes := range nodesByCapability {
		var (
			visited = make(map[*callgraph.Node]bfsState)
			q       []*callgraph.Node // queue for the BFS
		)
		// Initialize the queue to contain the nodes with the capability.
		for v := range nodes {
			if _, ok := safe[v]; ok {
				continue
			}
			q = append(q, v)
			visited[v] = bfsState{}
			// Skipping cases where v.Func.Package() doesn't exist.
			if v.Func.Package() == nil {
				continue
			}
			if _, ok := queriedPackages[v.Func.Package().Pkg]; ok {
				// v itself is in one of the queried packages.  Call fn here because
				// the BFS below will only call fn for functions that call v
				// directly or transitively.
				fn(cap, visited, v)
			}
		}
		sort.Sort(byName(q))
		// Perform a BFS backwards through the call graph from the interesting
		// nodes.
		for len(q) > 0 {
			v := q[0]
			q = q[1:]
			var incomingEdges []*callgraph.Edge
			calleeName := v.Func.String()
			for _, edge := range v.In {
				callerName := edge.Caller.Func.String()
				if classifier.IncludeCall(callerName, calleeName) {
					incomingEdges = append(incomingEdges, edge)
				}
			}
			sort.Sort(byCallerName(incomingEdges))
			for _, edge := range incomingEdges {
				w := edge.Caller
				if w.Func == nil {
					// Synthetic nodes may not have this information.
					continue
				}
				if _, ok := safe[w]; ok {
					continue
				}
				if _, ok := visited[w]; ok {
					// We have already visited w.
					continue
				}
				if _, ok := allNodesWithExplicitCapability[w]; ok {
					// w already has an explicit categorization.
					continue
				}
				visited[w] = bfsState{edge: edge}
				q = append(q, w)
				if w.Func.Package() != nil {
					if _, ok := queriedPackages[w.Func.Package().Pkg]; ok {
						fn(cap, visited, w)
					}
				}
			}
		}
	}
}
