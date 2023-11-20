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

// Config holds configuration for the analyzer.
type Config struct {
	Classifier     Classifier
	DisableBuiltin bool
}

// Classifier is an interface for types that help map code features to
// capabilities.
type Classifier interface {
	// FunctionCategory returns a Category for the given function specified by
	// a package name and function name.  Examples of function names include
	// "math.Cos", "(time.Time).Clock", and "(*sync.Cond).Signal".
	//
	// If the return value is Unspecified, then we have not declared it to be
	// either safe or unsafe, so its descendants will have to be considered by the
	// static analysis.
	FunctionCategory(pkg string, name string) cpb.Capability

	// IncludeCall returns true if a call from one function to another should be
	// considered when searching for transitive capabilities.  Usually this should
	// return true, unless there is some reason to know that the particular call
	// cannot lead to additional capabilities for a function.
	IncludeCall(caller string, callee string) bool
}

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
func GetCapabilityInfo(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) *cpb.CapabilityInfoList {
	type output struct {
		*cpb.CapabilityInfo
		*ssa.Function // used for sorting
	}
	var caps []output
	forEachPath(pkgs, queriedPackages,
		func(cap cpb.Capability, nodes map[*callgraph.Node]bfsState,
			v *callgraph.Node,
		) {
			i := 0
			c := cpb.CapabilityInfo{}
			fn := v.Func
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
			caps = append(caps, output{&c, fn})
		}, config)
	sort.Slice(caps, func(i, j int) bool {
		if x, y := caps[i].CapabilityInfo.GetCapability(), caps[j].CapabilityInfo.GetCapability(); x != y {
			return x < y
		}
		return funcCompare(caps[i].Function, caps[j].Function) < 0
	})
	cil := &cpb.CapabilityInfoList{
		CapabilityInfo: make([]*cpb.CapabilityInfo, len(caps)),
		ModuleInfo:     collectModuleInfo(pkgs),
		PackageInfo:    collectPackageInfo(pkgs),
	}
	for i := range caps {
		cil.CapabilityInfo[i] = caps[i].CapabilityInfo
	}
	return cil
}

type CapabilityCounter struct {
	capability       cpb.Capability
	count            int64
	direct_count     int64
	transitive_count int64
	example          []*cpb.Function
}

// GetCapabilityStats analyzes the packages in pkgs.  For each function in
// those packages which have a path in the callgraph to an "interesting"
// function (see the "interesting" package), we give aggregated statistics
// about the capability usage.
func GetCapabilityStats(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) *cpb.CapabilityStatList {
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
			var n string
			var incomingEdge *callgraph.Edge
			isDirect := true
			e := []*cpb.Function{}
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
				e = append(e, fn)
				if i == 0 {
					n = v.Func.Package().Pkg.Path()
				}
				i++
				if pName := packagePath(v.Func); n != pName && !isStdLib(pName) {
					isDirect = false
				}
				incomingEdge, v = nodes[v].edge, nodes[v].next()
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
				cm[cap.String()] = &CapabilityCounter{example: e}
			} else {
				cm[cap.String()].example = e
			}
		}, config)
	for _, counts := range cm {
		cs = append(cs, &cpb.CapabilityStats{
			Capability:      &counts.capability,
			Count:           &counts.count,
			DirectCount:     &counts.direct_count,
			TransitiveCount: &counts.transitive_count,
			ExampleCallpath: counts.example,
		})
	}
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].GetCapability() < cs[j].GetCapability()
	})
	return &cpb.CapabilityStatList{
		CapabilityStats: cs,
		ModuleInfo:      collectModuleInfo(pkgs),
	}
}

// GetCapabilityCount analyzes the packages in pkgs.  For each function in
// those packages which have a path in the callgraph to an "interesting"
// function (see the "interesting" package), we give an aggregate count of the
// capability usage.
func GetCapabilityCounts(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) *cpb.CapabilityCountList {
	cm := make(map[string]int64)
	forEachPath(pkgs, queriedPackages,
		func(cap cpb.Capability, nodes map[*callgraph.Node]bfsState, v *callgraph.Node) {
			if _, ok := cm[cap.String()]; !ok {
				cm[cap.String()] = 1
			} else {
				cm[cap.String()] += 1
			}
		}, config)
	return &cpb.CapabilityCountList{
		CapabilityCounts: cm,
		ModuleInfo:       collectModuleInfo(pkgs),
	}
}

// searchBackwardsFromCapabilities returns the set of all function nodes that
// have a path to a function with some capability.
func searchBackwardsFromCapabilities(nodesByCapability nodesetPerCapability, safe nodeset, classifier Classifier) nodeset {
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
	classifier Classifier,
	outputCall func(from, to *callgraph.Node),
	outputCapability func(fn *callgraph.Node, c cpb.Capability),
) {
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
	config *Config,
	outputCall func(from, to *callgraph.Node),
	outputCapability func(fn *callgraph.Node, c cpb.Capability),
) {
	safe, nodesByCapability, extraNodesByCapability := getPackageNodesWithCapability(pkgs, config)
	nodesByCapability, allNodesWithExplicitCapability := mergeCapabilities(nodesByCapability, extraNodesByCapability)
	extraNodesByCapability = nil

	canReachCapability := searchBackwardsFromCapabilities(nodesByCapability, safe, config.Classifier)

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
		config.Classifier,
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
	config *Config,
) (safe nodeset, nodesByCapability, extraNodesByCapability nodesetPerCapability) {
	graph, ssaProg, allFunctions := buildGraph(pkgs, true)
	unsafePointerFunctions := findUnsafePointerConversions(pkgs, ssaProg, allFunctions)
	ssaProg = nil // possibly save memory; we don't use ssaProg again
	safe, nodesByCapability = getNodeCapabilities(graph, config.Classifier)

	if !config.DisableBuiltin {
		extraNodesByCapability = getExtraNodesByCapability(graph, allFunctions, unsafePointerFunctions)
	}
	return safe, nodesByCapability, extraNodesByCapability
}

func getExtraNodesByCapability(graph *callgraph.Graph, allFunctions map[*ssa.Function]bool, unsafePointerFunctions map[*ssa.Function]struct{}) nodesetPerCapability {
	// Find functions that copy reflect.Value objects in a way that could
	// possibly cause a data race, and add their nodes to
	// extraNodesByCapability[Capability_CAPABILITY_REFLECT].
	extraNodesByCapability := make(nodesetPerCapability)
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
	return extraNodesByCapability
}

// findUnsafePointerConversions uses analysis of the syntax tree to find
// functions which convert unsafe.Pointer values to another type.
func findUnsafePointerConversions(pkgs []*packages.Package, ssaProg *ssa.Program, allFunctions map[*ssa.Function]bool) (unsafePointer map[*ssa.Function]struct{}) {
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
	for f := range allFunctions {
		if _, ok := unsafeFunctionNodes[f.Syntax()]; ok {
			unsafePointerFunctions[f] = struct{}{}
		}
	}
	for _, pkg := range ssaProg.AllPackages() {
		if _, ok := packagesWithUnsafePointerUseInInitialization[pkg.Pkg]; ok {
			// This package had an unsafe.Pointer conversion in the initialization
			// expression for a package-scoped variable, so we add the package's
			// "init" function to unsafePointerFunctions.
			// There will always be an init function for each package; if one
			// didn't exist in the source, a synthetic one will have been
			// created.
			if f := pkg.Func("init"); f != nil {
				unsafePointerFunctions[f] = struct{}{}
			}
		}
	}
	return unsafePointerFunctions
}

func getNodeCapabilities(graph *callgraph.Graph,
	classifier Classifier,
) (safe nodeset, nodesByCapability nodesetPerCapability) {
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
	fn func(cpb.Capability, map[*callgraph.Node]bfsState, *callgraph.Node), config *Config,
) {
	safe, nodesByCapability, extraNodesByCapability := getPackageNodesWithCapability(pkgs, config)
	nodesByCapability, allNodesWithExplicitCapability := mergeCapabilities(nodesByCapability, extraNodesByCapability)
	extraNodesByCapability = nil // we don't use extraNodesByCapability again.
	var caps []cpb.Capability
	for cap := range nodesByCapability {
		caps = append(caps, cap)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })
	for _, cap := range caps {
		nodes := nodesByCapability[cap]
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
		}
		sort.Sort(byFunction(q))
		for _, v := range q {
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
		// Perform a BFS backwards through the call graph from the interesting
		// nodes.
		for len(q) > 0 {
			v := q[0]
			q = q[1:]
			var incomingEdges []*callgraph.Edge
			calleeName := v.Func.String()
			for _, edge := range v.In {
				callerName := edge.Caller.Func.String()
				if config.Classifier.IncludeCall(callerName, calleeName) {
					incomingEdges = append(incomingEdges, edge)
				}
			}
			sort.Sort(byCaller(incomingEdges))
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
