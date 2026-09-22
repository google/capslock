// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/types"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
)

// CapabilitySet represents a set of Capslock capabilities.
// A nil *CapabilitySet represents the set of all capabilities.
type CapabilitySet struct {
	capabilities map[string]struct{}
	negated      bool
}

// Has returns whether c is a member of cs.
func (cs *CapabilitySet) Has(c string) bool {
	if cs == nil {
		return true
	}
	_, ok := cs.capabilities[c]
	return ok != cs.negated
}

// NewCapabilitySet returns a *CapabilitySet parsed from a string.
//
// If cs is empty, a nil *CapabilitySet is returned, which represents the set
// of all capabilities.  Otherwise, cs should be a comma-separated list of
// capabilities.  Optionally, all capabilities can be prefixed with '-' to
// specify the capabilities to exclude from the set.
func NewCapabilitySet(cs string) (*CapabilitySet, error) {
	if len(cs) == 0 {
		return nil, nil
	}
	out := make(map[string]struct{})
	negated := false
	for i, s := range strings.Split(cs, ",") {
		if len(s) == 0 {
			return nil, fmt.Errorf("empty capability in list: %q", cs)
		}
		neg := s[0] == '-'
		if neg {
			s = s[1:]
		}
		if i > 0 && neg != negated {
			return nil, fmt.Errorf("mix of negated and unnegated capabilities specified: %q", cs)
		}
		negated = neg
		// Capability strings previously would begin with "CAPABILITY_", but new
		// ones do not.  Support the old form for backwards-compatibility.
		out[strings.TrimPrefix(s, "CAPABILITY_")] = struct{}{}
	}
	return &CapabilitySet{out, negated}, nil
}

func graphOutput(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) error {
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	gb := newGraphBuilder(w, func(v interface{}) string {
		switch v := v.(type) {
		case *callgraph.Node:
			if v.Func != nil {
				return v.Func.String()
			}
			return strconv.Itoa(v.ID)
		case string:
			// A capability name.
			return v
		default:
			panic("unexpected node type")
		}
	})
	callEdge := func(edge *callgraph.Edge) {
		gb.Edge(edge.Caller, edge.Callee)
	}
	capabilityEdge := func(fn *callgraph.Node, c string) {
		gb.Edge(fn, c)
	}
	var filter func(c string) bool
	if config.CapabilitySet != nil {
		filter = config.CapabilitySet.Has
	}
	CapabilityGraph(pkgs, queriedPackages, config, nil, callEdge, capabilityEdge, filter)
	gb.Done()
	return w.Flush()
}

type graphJSONOutputInfo struct {
	Graphs []graphJSONGraph `json:"graphs"`
}

type graphJSONGraph struct {
	Root         string          `json:"root,omitempty"`
	Roots        []string        `json:"roots,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
	Nodes        []graphJSONNode `json:"nodes"`
	Edges        []graphJSONEdge `json:"edges"`
}

type graphJSONNode struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Package string `json:"package,omitempty"`
}

type graphJSONEdge struct {
	From string         `json:"from"`
	To   string         `json:"to"`
	Kind string         `json:"kind"`
	Site *graphJSONSite `json:"site,omitempty"`
}

type graphJSONSite struct {
	Filename string `json:"filename"`
	Line     int64  `json:"line"`
	Column   int64  `json:"column"`
}

func graphJSONOutput(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) error {
	out, err := buildGraphJSON(pkgs, queriedPackages, config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func buildGraphJSON(pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) (*graphJSONOutputInfo, error) {
	if config.GraphFunction != "" && config.GraphPerFunction {
		return nil, fmt.Errorf("-graph_function and -graph_per_function cannot be used together")
	}
	safe, nodesByCapability, extraNodesByCapability := getPackageNodesWithCapability(pkgs, config)
	nodesByCapability, allNodesWithExplicitCapability := mergeCapabilities(nodesByCapability, extraNodesByCapability)
	extraNodesByCapability = nil

	nodesByCapability = filterNodesByCapability(nodesByCapability, config.CapabilitySet)
	bfsFromCapabilities := searchBackwardsFromCapabilities(nodesByCapability, safe, allNodesWithExplicitCapability, config.Classifier)

	roots := reachableQueriedNodes(bfsFromCapabilities, queriedPackages)
	if config.GraphFunction != "" {
		root, ok := findGraphRoot(roots, config.GraphFunction)
		if !ok {
			return nil, fmt.Errorf("function %q was not found among queried functions that reach the selected capabilities", config.GraphFunction)
		}
		return &graphJSONOutputInfo{
			Graphs: []graphJSONGraph{
				collectGraphJSON([]*callgraph.Node{root}, nodesByCapability, allNodesWithExplicitCapability, bfsFromCapabilities, config.Classifier),
			},
		}, nil
	}

	if config.GraphPerFunction {
		out := &graphJSONOutputInfo{}
		for _, root := range roots {
			out.Graphs = append(out.Graphs,
				collectGraphJSON([]*callgraph.Node{root}, nodesByCapability, allNodesWithExplicitCapability, bfsFromCapabilities, config.Classifier))
		}
		return out, nil
	}

	return &graphJSONOutputInfo{
		Graphs: []graphJSONGraph{
			collectGraphJSON(roots, nodesByCapability, allNodesWithExplicitCapability, bfsFromCapabilities, config.Classifier),
		},
	}, nil
}

func filterNodesByCapability(nodesByCapability nodesetPerCapability, capabilitySet *CapabilitySet) nodesetPerCapability {
	if capabilitySet == nil {
		return nodesByCapability
	}
	filtered := make(nodesetPerCapability)
	for capability, nodes := range nodesByCapability {
		if capabilitySet.Has(capability) {
			filtered[capability] = nodes
		}
	}
	return filtered
}

func reachableQueriedNodes(bfsFromCapabilities bfsStateMap, queriedPackages map[*types.Package]struct{}) []*callgraph.Node {
	var roots []*callgraph.Node
	for v := range bfsFromCapabilities {
		if v.Func == nil || v.Func.Package() == nil {
			continue
		}
		if _, ok := queriedPackages[v.Func.Package().Pkg]; ok {
			roots = append(roots, v)
		}
	}
	sort.Sort(byFunction(roots))
	return roots
}

func findGraphRoot(roots []*callgraph.Node, name string) (*callgraph.Node, bool) {
	for _, root := range roots {
		if root.Func != nil && root.Func.String() == name {
			return root, true
		}
	}
	return nil, false
}

func collectGraphJSON(roots []*callgraph.Node, nodesByCapability nodesetPerCapability,
	allNodesWithExplicitCapability nodeset, bfsFromCapabilities bfsStateMap, classifier Classifier,
) graphJSONGraph {
	collector := newGraphJSONCollector(roots)
	startNodes := make(nodeset)
	for _, root := range roots {
		startNodes[root] = struct{}{}
	}
	searchForwardsFromQueriedFunctions(
		startNodes,
		nodesByCapability,
		allNodesWithExplicitCapability,
		bfsFromCapabilities,
		classifier,
		func(_ bfsStateMap, node *callgraph.Node, _ bfsStateMap) {
			collector.addFunctionNode(node)
		},
		func(edge *callgraph.Edge) {
			collector.addFunctionNode(edge.Caller)
			collector.addFunctionNode(edge.Callee)
			collector.addCallEdge(edge)
		},
		func(fn *callgraph.Node, capability string) {
			collector.addFunctionNode(fn)
			collector.addCapabilityNode(capability)
			collector.addCapabilityEdge(fn, capability)
		})
	return collector.graph()
}

type graphJSONCollector struct {
	roots        []string
	nodes        map[string]graphJSONNode
	edges        map[string]graphJSONEdge
	capabilities map[string]struct{}
}

func newGraphJSONCollector(roots []*callgraph.Node) *graphJSONCollector {
	var rootNames []string
	for _, root := range roots {
		rootNames = append(rootNames, graphNodeID(root))
	}
	sort.Strings(rootNames)
	return &graphJSONCollector{
		roots:        rootNames,
		nodes:        make(map[string]graphJSONNode),
		edges:        make(map[string]graphJSONEdge),
		capabilities: make(map[string]struct{}),
	}
}

func (c *graphJSONCollector) addFunctionNode(node *callgraph.Node) {
	if node == nil {
		return
	}
	id := graphNodeID(node)
	n := graphJSONNode{
		ID:   id,
		Kind: "function",
	}
	if pkg := nodeToPackage(node); pkg != nil {
		n.Package = pkg.Path()
	}
	c.nodes[id] = n
}

func (c *graphJSONCollector) addCapabilityNode(capability string) {
	id := graphCapabilityID(capability)
	c.nodes[id] = graphJSONNode{
		ID:   id,
		Kind: "capability",
	}
	c.capabilities[capability] = struct{}{}
}

func (c *graphJSONCollector) addCallEdge(edge *callgraph.Edge) {
	e := graphJSONEdge{
		From: graphNodeID(edge.Caller),
		To:   graphNodeID(edge.Callee),
		Kind: "call",
		Site: graphJSONSiteFromEdge(edge),
	}
	c.edges[graphJSONEdgeKey(e)] = e
}

func (c *graphJSONCollector) addCapabilityEdge(fn *callgraph.Node, capability string) {
	e := graphJSONEdge{
		From: graphNodeID(fn),
		To:   graphCapabilityID(capability),
		Kind: "capability",
	}
	c.edges[graphJSONEdgeKey(e)] = e
}

func (c *graphJSONCollector) graph() graphJSONGraph {
	g := graphJSONGraph{
		Capabilities: sortedStrings(c.capabilities),
		Nodes:        sortedGraphJSONNodes(c.nodes),
		Edges:        sortedGraphJSONEdges(c.edges),
	}
	if len(c.roots) == 1 {
		g.Root = c.roots[0]
	} else {
		g.Roots = c.roots
	}
	return g
}

func graphNodeID(node *callgraph.Node) string {
	if node == nil {
		return ""
	}
	if node.Func != nil {
		return node.Func.String()
	}
	return strconv.Itoa(node.ID)
}

func graphCapabilityID(capability string) string {
	return "CAPABILITY_" + capability
}

func graphJSONSiteFromEdge(edge *callgraph.Edge) *graphJSONSite {
	if position := callsitePosition(edge); position.IsValid() {
		return &graphJSONSite{
			Filename: position.Filename,
			Line:     int64(position.Line),
			Column:   int64(position.Column),
		}
	}
	return nil
}

func graphJSONEdgeKey(e graphJSONEdge) string {
	return e.Kind + "\x00" + e.From + "\x00" + e.To
}

func sortedGraphJSONNodes(nodes map[string]graphJSONNode) []graphJSONNode {
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]graphJSONNode, 0, len(ids))
	for _, id := range ids {
		out = append(out, nodes[id])
	}
	return out
}

func sortedGraphJSONEdges(edges map[string]graphJSONEdge) []graphJSONEdge {
	keys := make([]string, 0, len(edges))
	for key := range edges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]graphJSONEdge, 0, len(keys))
	for _, key := range keys {
		out = append(out, edges[key])
	}
	return out
}

func sortedStrings(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

type graphBuilder struct {
	io.Writer
	nodeNamer func(any) string
	done      bool
}

func newGraphBuilder(w io.Writer, nodeNamer func(any) string) graphBuilder {
	gb := graphBuilder{
		Writer:    w,
		nodeNamer: nodeNamer,
	}
	gb.Write([]byte("digraph {\n"))
	return gb
}

func (gb *graphBuilder) Edge(from, to interface{}) {
	if gb.done {
		panic("done")
	}
	gb.Write([]byte("\t"))
	gb.Write([]byte(`"`))
	gb.Write([]byte(strings.ReplaceAll(gb.nodeNamer(from), `"`, `\"`)))
	gb.Write([]byte(`" -> "`))
	gb.Write([]byte(strings.ReplaceAll(gb.nodeNamer(to), `"`, `\"`)))
	gb.Write([]byte("\"\n"))
}

func (gb *graphBuilder) Done() {
	if gb.done {
		panic("done")
	}
	gb.Write([]byte("}\n"))
	gb.done = true
}
