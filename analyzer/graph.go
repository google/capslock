// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"bufio"
	"go/types"
	"io"
	"os"
	"strconv"
	"strings"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
)

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
	callEdge := func(caller, callee *callgraph.Node) {
		gb.Edge(caller, callee)
	}
	capabilityEdge := func(fn *callgraph.Node, c cpb.Capability) {
		gb.Edge(fn, c)
	}
	CapabilityGraph(pkgs, queriedPackages, config, callEdge, capabilityEdge)
	gb.Done()
	return w.Flush()
}

type graphBuilder struct {
	io.Writer
	nodeNamer func(any) string
	started   bool
	done      bool
}

func newGraphBuilder(w io.Writer, nodeNamer func(any) string) graphBuilder {
	return graphBuilder{
		Writer:    w,
		nodeNamer: nodeNamer,
	}
}

func (gb *graphBuilder) Edge(from, to interface{}) {
	if gb.done {
		panic("done")
	}
	if !gb.started {
		gb.Write([]byte("digraph {\n"))
		gb.started = true
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
