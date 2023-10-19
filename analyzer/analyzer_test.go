// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"os"
	"testing"

	"github.com/google/capslock/interesting"
	cpb "github.com/google/capslock/proto"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

var filemap = map[string]string{"testlib/foo.go": `package testlib

import "os"

func Foo() {
	println(os.Getpid())
}`}

func TestAnalysis(t *testing.T) {
	dir, cleanup, err := analysistest.WriteFiles(filemap)
	if err != nil {
		t.Fatalf("analysistest.WriteFiles: %v", err)
	}
	defer cleanup()
	env := []string{"GOPATH=" + dir, "GO111MODULE=off", "GOPROXY=off"}
	cfg := &packages.Config{
		Mode: PackagesLoadModeNeeded,
		Dir:  dir,
		Env:  append(os.Environ(), env...),
	}
	pkgs, err := packages.Load(cfg, "testlib")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	queriedPackages := GetQueriedPackages(pkgs)
	cil := GetCapabilityInfo(pkgs, queriedPackages, &Config{
		Classifier:     interesting.DefaultClassifier(),
		DisableBuiltin: false,
	})
	expected := &cpb.CapabilityInfoList{
		CapabilityInfo: []*cpb.CapabilityInfo{{
			PackageName: proto.String("testlib"),
			Capability:  cpb.Capability_CAPABILITY_READ_SYSTEM_STATE.Enum(),
			Path: []*cpb.Function{
				&cpb.Function{Name: proto.String("testlib.Foo")},
				&cpb.Function{Name: proto.String("os.Getpid")},
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
