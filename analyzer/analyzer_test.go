// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"fmt"
	"go/types"
	"os"
	"reflect"
	"testing"

	"github.com/google/capslock/interesting"
	cpb "github.com/google/capslock/proto"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

var filemap = map[string]string{"testlib/foo.go": `package testlib

import "os"

func Foo() { println(os.Getpid()) }
func A() { B(); C() }
func B() { C() }
func C() { println(os.IsExist(nil)) }
`}

func setup() (pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, cleanup func(), err error) {
	dir, cleanup, err := analysistest.WriteFiles(filemap)
	if err != nil {
		return nil, nil, cleanup, fmt.Errorf("analysistest.WriteFiles: %w", err)
	}
	env := []string{"GOPATH=" + dir, "GO111MODULE=off", "GOPROXY=off"}
	cfg := &packages.Config{
		Mode: PackagesLoadModeNeeded,
		Dir:  dir,
		Env:  append(os.Environ(), env...),
	}
	pkgs, err = packages.Load(cfg, "testlib")
	if err != nil {
		return nil, nil, cleanup, fmt.Errorf("packages.Load: %w", err)
	}
	queriedPackages = GetQueriedPackages(pkgs)
	return pkgs, queriedPackages, cleanup, nil
}

func TestAnalysis(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup()
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     interesting.DefaultClassifier(),
		DisableBuiltin: false,
	})
	expected := &cpb.CapabilityInfoList{
		CapabilityInfo: []*cpb.CapabilityInfo{{
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.Foo"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.Getpid"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}},
	}
	opts := []cmp.Option{
		protocmp.Transform(),
		protocmp.IgnoreFields(&cpb.CapabilityInfoList{}, "package_info"),
		protocmp.IgnoreFields(&cpb.CapabilityInfo{}, "dep_path"),
		protocmp.IgnoreFields(&cpb.Function{}, "site"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "filename"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "line"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "column"),
	}
	if diff := cmp.Diff(expected, cil, opts...); diff != "" {
		t.Errorf("GetCapabilityInfo(%v): got %v, want %v; diff %s",
			filemap, cil, expected, diff)
	}
}

func TestGraph(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup()
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	nodes := make(map[string]struct{})
	calls := make(map[[2]string]struct{})
	caps := make(map[string][]cpb.Capability)
	CapabilityGraph(pkgs, queriedPackages,
		&Config{
			Classifier:     interesting.DefaultClassifier(),
			DisableBuiltin: false,
		},
		func(_ bfsStateMap, node *callgraph.Node, _ bfsStateMap) {
			nodes[node.Func.String()] = struct{}{}
		},
		func(edge *callgraph.Edge) {
			calls[[2]string{edge.Caller.Func.String(), edge.Callee.Func.String()}] = struct{}{}
		},
		func(fn *callgraph.Node, c cpb.Capability) {
			f := fn.Func.String()
			caps[f] = append(caps[f], c)
		})
	expectedNodes := map[string]struct{}{
		"testlib.Foo": {},
		"os.Getpid":   {},
	}
	expectedCalls := map[[2]string]struct{}{
		{"testlib.Foo", "os.Getpid"}: {},
	}
	expectedCaps := map[string][]cpb.Capability{
		"os.Getpid": {cpb.Capability_CAPABILITY_READ_SYSTEM_STATE},
	}
	if !reflect.DeepEqual(nodes, expectedNodes) {
		t.Errorf("CapabilityGraph(%v): got nodes %v want %v",
			filemap, nodes, expectedNodes)
	}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Errorf("CapabilityGraph(%v): got calls %v want %v",
			filemap, calls, expectedCalls)
	}
	if !reflect.DeepEqual(caps, expectedCaps) {
		t.Errorf("CapabilityGraph(%v): got capabilities %v want %v",
			filemap, caps, expectedCaps)
	}
}

// testClassifier is used for testing that non-default classifiers work
// correctly.
type testClassifier struct{}

func (testClassifier) FunctionCategory(pkg string, name string) cpb.Capability {
	// Only categorize os.IsExist as having a capability.
	if pkg == "os" && name == "os.IsExist" {
		return cpb.Capability_CAPABILITY_FILES
	}
	return 0
}
func (testClassifier) IncludeCall(edge *callgraph.Edge) bool {
	// Exclude calls from A to C.
	caller := edge.Caller.Func.String()
	callee := edge.Callee.Func.String()
	return !(caller == "testlib.A" && callee == "testlib.C")
}

func TestAnalysisWithClassifier(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup()
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     testClassifier{},
		DisableBuiltin: true,
	})
	expected := &cpb.CapabilityInfoList{
		CapabilityInfo: []*cpb.CapabilityInfo{{
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.A"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("testlib.B"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("testlib.C"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.IsExist"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}, {
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.B"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("testlib.C"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.IsExist"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}, {
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.C"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.IsExist"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}},
	}
	opts := []cmp.Option{
		protocmp.Transform(),
		protocmp.SortRepeated(func(a, b *cpb.CapabilityInfo) bool {
			return a.GetDepPath() < b.GetDepPath()
		}),
		protocmp.IgnoreFields(&cpb.CapabilityInfoList{}, "package_info"),
		protocmp.IgnoreFields(&cpb.CapabilityInfo{}, "dep_path"),
		protocmp.IgnoreFields(&cpb.Function{}, "site"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "filename"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "line"),
		protocmp.IgnoreFields(&cpb.Function_Site{}, "column"),
	}
	if diff := cmp.Diff(expected, cil, opts...); diff != "" {
		t.Errorf("GetCapabilityInfo(%v): got %v, want %v; diff %s",
			filemap, cil, expected, diff)
	}
}

func TestGraphWithClassifier(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup()
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	nodes := make(map[string]struct{})
	calls := make(map[[2]string]struct{})
	caps := make(map[string][]cpb.Capability)
	CapabilityGraph(pkgs, queriedPackages,
		&Config{
			Classifier:     testClassifier{},
			DisableBuiltin: true,
		},
		func(_ bfsStateMap, node *callgraph.Node, _ bfsStateMap) {
			nodes[node.Func.String()] = struct{}{}
		},
		func(edge *callgraph.Edge) {
			calls[[2]string{edge.Caller.Func.String(), edge.Callee.Func.String()}] = struct{}{}
		},
		func(fn *callgraph.Node, c cpb.Capability) {
			f := fn.Func.String()
			caps[f] = append(caps[f], c)
		})
	expectedNodes := map[string]struct{}{
		"testlib.A":  {},
		"testlib.B":  {},
		"testlib.C":  {},
		"os.IsExist": {},
	}
	expectedCalls := map[[2]string]struct{}{
		{"testlib.A", "testlib.B"}:  {},
		{"testlib.B", "testlib.C"}:  {},
		{"testlib.C", "os.IsExist"}: {},
	}
	expectedCaps := map[string][]cpb.Capability{
		"os.IsExist": {cpb.Capability_CAPABILITY_FILES},
	}
	if !reflect.DeepEqual(nodes, expectedNodes) {
		t.Errorf("CapabilityGraph(%v): got nodes %v want %v",
			filemap, nodes, expectedNodes)
	}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Errorf("CapabilityGraph(%v): got calls %v want %v",
			filemap, calls, expectedCalls)
	}
	if !reflect.DeepEqual(caps, expectedCaps) {
		t.Errorf("CapabilityGraph(%v): got capabilities %v want %v",
			filemap, caps, expectedCaps)
	}
}
