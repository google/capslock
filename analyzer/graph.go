// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"bufio"
	"fmt"
	"go/types"
	"io"
	"os"
	"strconv"
	"strings"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
)

// CapabilitySet represents a set of Capslock capabilities.
// A nil *CapabilitySet represents the set of all capabilities.
type CapabilitySet struct {
	capabilities map[cpb.Capability]struct{}
	negated      bool
}

// Has returns whether c is a member of cs.
func (cs *CapabilitySet) Has(c cpb.Capability) bool {
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
	out := make(map[cpb.Capability]struct{})
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
		c, ok := cpb.Capability_value[s]
		if !ok {
			c, ok = cpb.Capability_value["CAPABILITY_"+s]
		}
		if !ok {
			return nil, fmt.Errorf("unknown capability %q", s)
		}
		out[cpb.Capability(c)] = struct{}{}
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
		case cpb.Capability:
			return v.String()
		default:
			panic("unexpected node type")
		}
	})
	callEdge := func(edge *callgraph.Edge) {
		gb.Edge(edge.Caller, edge.Callee)
	}
	capabilityEdge := func(fn *callgraph.Node, c cpb.Capability) {
		gb.Edge(fn, c)
	}
	var filter func(c cpb.Capability) bool
	if config.CapabilitySet != nil {
		filter = config.CapabilitySet.Has
	}
	CapabilityGraph(pkgs, queriedPackages, config, nil, callEdge, capabilityEdge, filter)
	gb.Done()
	return w.Flush()
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
