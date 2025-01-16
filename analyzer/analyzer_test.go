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
func Bar() { println(os.Getpid()) }
func A() { B(); C() }
func B() { C() }
func C() { println(os.IsExist(nil)) }
`}

// setup contains common code for loading test packages.
func setup(filemap map[string]string, pkg string) (pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, cleanup func(), err error) {
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
	pkgs, err = packages.Load(cfg, pkg)
	if err != nil {
		return nil, nil, cleanup, fmt.Errorf("packages.Load: %w", err)
	}
	queriedPackages = GetQueriedPackages(pkgs)
	return pkgs, queriedPackages, cleanup, nil
}

func TestAnalysis(t *testing.T) {
	t.Run("include paths", func(t *testing.T) { testAnalysis(t, false) })
	t.Run("omit paths", func(t *testing.T) { testAnalysis(t, true) })
}

func testAnalysis(t *testing.T, omitPaths bool) {
	pkgs, queriedPackages, cleanup, err := setup(filemap, "testlib")
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     interesting.DefaultClassifier(),
		DisableBuiltin: false,
		OmitPaths:      omitPaths,
	})
	expected := &cpb.CapabilityInfoList{
		CapabilityInfo: []*cpb.CapabilityInfo{{
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
			DepPath:     proto.String("testlib.Bar os.Getpid"),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.Bar"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.Getpid"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}, {
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
			DepPath:     proto.String("testlib.Foo os.Getpid"),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.Foo"), Package: proto.String("testlib")},
				&cpb.Function{Name: proto.String("os.Getpid"), Package: proto.String("os")},
			},
			PackageDir:     proto.String("testlib"),
			CapabilityType: cpb.CapabilityType_CAPABILITY_TYPE_DIRECT.Enum(),
		}},
	}
	if omitPaths {
		for _, ci := range expected.CapabilityInfo {
			ci.DepPath = nil
			ci.Path = ci.Path[:1]
		}
	}
	opts := []cmp.Option{
		protocmp.Transform(),
		protocmp.IgnoreFields(&cpb.CapabilityInfoList{}, "package_info"),
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
	pkgs, queriedPackages, cleanup, err := setup(filemap, "testlib")
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
		},
		nil)
	expectedNodes := map[string]struct{}{
		"testlib.Foo": {},
		"testlib.Bar": {},
		"os.Getpid":   {},
	}
	expectedCalls := map[[2]string]struct{}{
		{"testlib.Foo", "os.Getpid"}: {},
		{"testlib.Bar", "os.Getpid"}: {},
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
type testClassifier struct {
	// functions is a map from {package name, function name} to the capability
	// the classifier should return.
	functions map[[2]string]cpb.Capability
	// ignoredEdges is a set of {caller, callee} pairs denoting callgraph edges
	// the classifier thinks should be ignored.
	ignoredEdges map[[2]string]struct{}
}

func (t *testClassifier) FunctionCategory(pkg string, name string) cpb.Capability {
	return t.functions[[2]string{pkg, name}]
}

func (t *testClassifier) IncludeCall(edge *callgraph.Edge) bool {
	caller := edge.Caller.Func.String()
	callee := edge.Callee.Func.String()
	_, ignore := t.ignoredEdges[[2]string{caller, callee}]
	return !ignore
}

var testClassifier1 = testClassifier{
	// Only categorize os.IsExist as having a capability.
	functions: map[[2]string]cpb.Capability{
		{"os", "os.IsExist"}: cpb.Capability_CAPABILITY_FILES,
	},
	// Exclude calls from A to C.
	ignoredEdges: map[[2]string]struct{}{
		{"testlib.A", "testlib.C"}: struct{}{},
	},
}

func TestAnalysisWithClassifier(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup(filemap, "testlib")
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     &testClassifier1,
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
	pkgs, queriedPackages, cleanup, err := setup(filemap, "testlib")
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
			Classifier:     &testClassifier1,
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
		},
		nil)
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

func TestAnalysisPackageGranularity(t *testing.T) {
	pkgs, queriedPackages, cleanup, err := setup(filemap, "testlib")
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     interesting.DefaultClassifier(),
		DisableBuiltin: false,
		Granularity:    GranularityPackage,
	})
	expected := &cpb.CapabilityInfoList{
		CapabilityInfo: []*cpb.CapabilityInfo{{
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.Bar"), Package: proto.String("testlib")},
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

func TestNewCapabilitySet(t *testing.T) {
	for _, test := range []struct {
		list             string
		wantCapabilities map[cpb.Capability]struct{}
		wantNegated      bool
	}{
		{
			list: "NETWORK",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_NETWORK: struct{}{},
			},
			wantNegated: false,
		},
		{
			list:             "",
			wantCapabilities: nil,
			wantNegated:      true,
		},
		{
			list: "-NETWORK",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_NETWORK: struct{}{},
			},
			wantNegated: true,
		},
		{
			list: "CAPABILITY_NETWORK",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_NETWORK: struct{}{},
			},
			wantNegated: false,
		},
		{
			list: "NETWORK,FILES",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_NETWORK: struct{}{},
				cpb.Capability_CAPABILITY_FILES:   struct{}{},
			},
			wantNegated: false,
		},
		{
			list: "-NETWORK,-CAPABILITY_FILES",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_NETWORK: struct{}{},
				cpb.Capability_CAPABILITY_FILES:   struct{}{},
			},
			wantNegated: true,
		},
		{
			list: "CAPABILITY_FILES,CAPABILITY_NETWORK,CAPABILITY_RUNTIME,CAPABILITY_READ_SYSTEM_STATE,CAPABILITY_MODIFY_SYSTEM_STATE,CAPABILITY_OPERATING_SYSTEM,CAPABILITY_SYSTEM_CALLS,CAPABILITY_ARBITRARY_EXECUTION,CAPABILITY_CGO,CAPABILITY_UNANALYZED,CAPABILITY_UNSAFE_POINTER,CAPABILITY_REFLECT,CAPABILITY_EXEC",
			wantCapabilities: map[cpb.Capability]struct{}{
				cpb.Capability_CAPABILITY_FILES:               struct{}{},
				cpb.Capability_CAPABILITY_NETWORK:             struct{}{},
				cpb.Capability_CAPABILITY_RUNTIME:             struct{}{},
				cpb.Capability_CAPABILITY_READ_SYSTEM_STATE:   struct{}{},
				cpb.Capability_CAPABILITY_MODIFY_SYSTEM_STATE: struct{}{},
				cpb.Capability_CAPABILITY_OPERATING_SYSTEM:    struct{}{},
				cpb.Capability_CAPABILITY_SYSTEM_CALLS:        struct{}{},
				cpb.Capability_CAPABILITY_ARBITRARY_EXECUTION: struct{}{},
				cpb.Capability_CAPABILITY_CGO:                 struct{}{},
				cpb.Capability_CAPABILITY_UNANALYZED:          struct{}{},
				cpb.Capability_CAPABILITY_UNSAFE_POINTER:      struct{}{},
				cpb.Capability_CAPABILITY_REFLECT:             struct{}{},
				cpb.Capability_CAPABILITY_EXEC:                struct{}{},
			},
			wantNegated: false,
		},
	} {
		cs, err := NewCapabilitySet(test.list)
		if err != nil {
			t.Errorf("NewCapabilitySet(%q): got err == %v, want nil error",
				test.list, err)
			continue
		}
		if test.wantCapabilities == nil {
			if cs != nil {
				t.Errorf("NewCapabilitySet(%q): got non-nil, want nil", test.list)
			}
			continue
		}
		if !reflect.DeepEqual(cs.capabilities, test.wantCapabilities) {
			t.Errorf("NewCapabilitySet(%q): got capabilities %v want %v",
				test.list, cs.capabilities, test.wantCapabilities)
		}
		if cs.negated != test.wantNegated {
			t.Errorf("NewCapabilitySet(%q): got negated = %v want %v",
				test.list, cs.negated, test.wantNegated)
		}
	}
	for _, list := range []string{
		"NOTWORK",
		"FILES!",
		"NETWORKFILES",
		"-NETWORK,FILES",
		"NETWORK,-FILES",
		",NETWORK",
		"NETWORK,",
		"NETWORK,,FILES",
		",",
		",,",
		"\x00",
	} {
		_, err := NewCapabilitySet(list)
		if err == nil {
			t.Errorf("NewCapabilitySet(%q): got err == nil, want error", list)
		}
	}
}

func TestIntermediatePackages(t *testing.T) {
	filemap := map[string]string{
		"p1/p1.go": `package p1; func Foo() { Bar() }; func Bar() { }`,
		"p2/p2.go": `package p2; import "p1"; func Foo() { p1.Foo() }`,
		"p3/p3.go": `package p3; import "p1"; func Foo() { p1.Foo() }; func Bar() { p1.Bar() }`,
		"p4/p4.go": `package p4; import "p2"; import "p3"; func Foo() { p2.Foo(); p3.Foo(); p3.Bar() }; func Bar() { }`,
	}
	classifier := testClassifier{
		functions: map[[2]string]cpb.Capability{
			{"p1", "p1.Foo"}: cpb.Capability_CAPABILITY_FILES,
			{"p1", "p1.Bar"}: cpb.Capability_CAPABILITY_MODIFY_SYSTEM_STATE,
			{"p4", "p4.Bar"}: cpb.Capability_CAPABILITY_READ_SYSTEM_STATE,
		},
		ignoredEdges: nil,
	}
	pkgs, queriedPackages, cleanup, err := setup(filemap, "p4")
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	for _, test := range []struct {
		capabilities string
		expected     *cpb.CapabilityInfoList
	}{
		{
			capabilities: "", // all
			expected: &cpb.CapabilityInfoList{
				CapabilityInfo: []*cpb.CapabilityInfo{
					{
						PackageName: proto.String("p1"),
						Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p2.Foo"), Package: proto.String("p2")},
							&cpb.Function{Name: proto.String("p1.Foo"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p1"),
					},
					{
						PackageName: proto.String("p2"),
						Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p2.Foo"), Package: proto.String("p2")},
							&cpb.Function{Name: proto.String("p1.Foo"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p2"),
					},
					{
						PackageName: proto.String("p3"),
						Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p3.Foo"), Package: proto.String("p3")},
							&cpb.Function{Name: proto.String("p1.Foo"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p3"),
					},
					{
						PackageName: proto.String("p4"),
						Capability:  cpb.Capability_CAPABILITY_FILES.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p2.Foo"), Package: proto.String("p2")},
							&cpb.Function{Name: proto.String("p1.Foo"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p4"),
					},
					{
						PackageName: proto.String("p4"),
						Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Bar"), Package: proto.String("p4")},
						},
						PackageDir: proto.String("p4"),
					},
					{
						PackageName: proto.String("p1"),
						Capability:  cpb.Capability_CAPABILITY_MODIFY_SYSTEM_STATE.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p3.Bar"), Package: proto.String("p3")},
							&cpb.Function{Name: proto.String("p1.Bar"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p1"),
					},
					{
						PackageName: proto.String("p3"),
						Capability:  cpb.Capability_CAPABILITY_MODIFY_SYSTEM_STATE.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p3.Bar"), Package: proto.String("p3")},
							&cpb.Function{Name: proto.String("p1.Bar"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p3"),
					},
					{
						PackageName: proto.String("p4"),
						Capability:  cpb.Capability_CAPABILITY_MODIFY_SYSTEM_STATE.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Foo"), Package: proto.String("p4")},
							&cpb.Function{Name: proto.String("p3.Bar"), Package: proto.String("p3")},
							&cpb.Function{Name: proto.String("p1.Bar"), Package: proto.String("p1")},
						},
						PackageDir: proto.String("p4"),
					},
				},
			},
		},
		{
			capabilities: "READ_SYSTEM_STATE",
			expected: &cpb.CapabilityInfoList{
				CapabilityInfo: []*cpb.CapabilityInfo{
					{
						PackageName: proto.String("p4"),
						Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
						Path: []*cpb.Function{
							&cpb.Function{Name: proto.String("p4.Bar"), Package: proto.String("p4")},
						},
						PackageDir: proto.String("p4"),
					},
				},
			},
		},
	} {
		cs, err := NewCapabilitySet(test.capabilities)
		if err != nil {
			t.Fatalf("NewCapabilitySet(%q): %v", test.capabilities, err)
		}
		cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
			Classifier:     &classifier,
			DisableBuiltin: true,
			Granularity:    GranularityIntermediate,
			CapabilitySet:  cs,
		})
		opts := []cmp.Option{
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b *cpb.CapabilityInfo) bool {
				if u, v := a.GetCapability(), b.GetCapability(); u != v {
					return u < v
				}
				return a.GetPackageDir() < b.GetPackageDir()
			}),
			protocmp.IgnoreFields(&cpb.CapabilityInfoList{}, "package_info"),
			protocmp.IgnoreFields(&cpb.CapabilityInfo{}, "dep_path"),
			protocmp.IgnoreFields(&cpb.CapabilityInfo{}, "capability_type"),
			protocmp.IgnoreFields(&cpb.Function{}, "site"),
			protocmp.IgnoreFields(&cpb.Function_Site{}, "filename"),
			protocmp.IgnoreFields(&cpb.Function_Site{}, "line"),
			protocmp.IgnoreFields(&cpb.Function_Site{}, "column"),
		}
		if diff := cmp.Diff(test.expected, cil, opts...); diff != "" {
			t.Errorf("GetCapabilityInfo: got %v, want %v; diff %s",
				cil, test.expected, diff)
		}
	}
}
