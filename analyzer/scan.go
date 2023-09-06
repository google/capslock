// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"bufio"
	"embed"
	"fmt"
	"go/types"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/google/capslock/interesting"
	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed static/*
var staticContent embed.FS

func RunCapslock(args []string, output string, pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier) error {
	if output == "compare" {
		if len(args) >= 1 {
			cil := GetCapabilityInfo(pkgs, queriedPackages, classifier)
			programName := "capslock"
			if a := os.Args; len(a) >= 1 {
				programName = a[0]
			}
			if len(args) != 1 {
				return fmt.Errorf("Usage: %s -output=compare <filename>; provided %v args", programName, len(args))
			}
			compareData, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from reading comparison file: %v", programName, err.Error())
			}
			baseline := new(cpb.CapabilityInfoList)
			err = protojson.Unmarshal(compareData, baseline)
			if err != nil {
				return fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from parsing comparison file: %v", programName, err.Error())
			}
			diffCapabilityInfoLists(baseline, cil)
		} else {
			return fmt.Errorf("compare function invoked but no comparison file provided")
		}
	} else if len(args) >= 1 {
		return fmt.Errorf("%s: unknown command", args)
	}
	return runAnalyzer(output, pkgs, queriedPackages, classifier)
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

func templateFormat(args ...interface{}) string {
	var format string
	if len(args) != 0 {
		format = args[0].(string)
	}
	var w strings.Builder
	switch format {
	case "":
		// "{{format}}" without arguments resets format.
		color.New(color.FgHiBlack).UnsetWriter(&w)
	case "intro", "callpath", "callpath-site":
		color.New(color.FgHiBlack).SetWriter(&w)
	case "highlight":
		color.New(color.FgCyan).SetWriter(&w)
	case "heading":
		color.New(color.FgHiWhite).SetWriter(&w)
	case "nocap":
		color.New(color.FgHiGreen).SetWriter(&w)
	case "capability":
		var capability string
		if s, ok := args[1].(fmt.Stringer); ok {
			capability = s.String()
		} else {
			capability, ok = args[1].(string)
		}
		switch capability {
		case "CAPABILITY_SAFE":
			color.New(color.FgHiGreen).SetWriter(&w)
		case "CAPABILITY_ARBITRARY_EXECUTION", "CAPABILITY_CGO", "CAPABILITY_UNSAFE_POINTER", "CAPABILITY_EXEC":
			color.New(color.FgHiRed).SetWriter(&w)
		default:
			color.New(color.FgHiYellow).SetWriter(&w)
		}
	}
	return w.String()
}

func runAnalyzer(output string, pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	classifier *interesting.Classifier) error {
	templateFuncMap := template.FuncMap{
		"format": templateFormat,
	}
	if output == "json" || output == "j" {
		cil := GetCapabilityInfo(pkgs, queriedPackages, classifier)
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(cil)
		if err != nil {
			return fmt.Errorf("internal error: couldn't marshal protocol buffer: %s", err.Error())
		}
		fmt.Println(string(b))
		return nil
	} else if output == "m" || output == "machine" {
		cil := GetCapabilityCounts(pkgs, queriedPackages, classifier)
		for c := range cil.CapabilityCounts {
			fmt.Println(c)
		}
		return nil
	} else if output == "v" || output == "verbose" {
		cil := GetCapabilityStats(pkgs, queriedPackages, classifier)
		ctm := template.Must(template.New("verbose.tmpl").Funcs(templateFuncMap).ParseFS(staticContent, "static/verbose.tmpl"))
		return ctm.Execute(os.Stdout, cil)
	} else if output == "g" || output == "graph" {
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
		CapabilityGraph(pkgs, queriedPackages, classifier, callEdge, capabilityEdge)
		gb.Done()
		return w.Flush()
	}
	cil := GetCapabilityCounts(pkgs, queriedPackages, classifier)
	ctm := template.Must(template.New("default.tmpl").Funcs(templateFuncMap).ParseFS(staticContent, "static/default.tmpl"))
	return ctm.Execute(os.Stdout, cil)
}

type capabilitySet map[cpb.Capability]*cpb.CapabilityInfo
type capabilitiesMap map[string]capabilitySet

// populateMap takes a CapabilityInfoList and returns a map from package
// directory and capability to a pointer to the corresponding entry in the
// input.
func populateMap(cil *cpb.CapabilityInfoList) capabilitiesMap {
	m := make(capabilitiesMap)
	for _, ci := range cil.GetCapabilityInfo() {
		dir := ci.GetPackageDir()
		capmap := m[dir]
		if capmap == nil {
			capmap = make(capabilitySet)
			m[dir] = capmap
		}
		capmap[ci.GetCapability()] = ci
	}
	return m
}

func diffCapabilityInfoLists(baseline, current *cpb.CapabilityInfoList) {
	baselineMap := populateMap(baseline)
	currentMap := populateMap(current)
	var packages []string
	for packageName := range baselineMap {
		packages = append(packages, packageName)
	}
	for packageName := range currentMap {
		if _, ok := baselineMap[packageName]; !ok {
			packages = append(packages, packageName)
		}
	}
	sort.Strings(packages)
	for _, packageName := range packages {
		b := baselineMap[packageName]
		c := currentMap[packageName]
		for capability := range c {
			if _, ok := b[capability]; !ok {
				fmt.Printf("Package %s has new capability %s compared to the baseline.\n",
					packageName, capability)
			}
		}
		for capability := range b {
			if _, ok := c[capability]; !ok {
				fmt.Printf("Package %s no longer has capability %s which was in the baseline.\n",
					packageName, capability)
			}
		}
	}
	os.Exit(0)
}
