// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package interesting

import (
	"strings"
	"testing"

	cpb "github.com/google/capslock/proto"
)

const (
	userCapabilityMap = `
# Override existing package capability
package runtime CAPABILITY_NETWORK
# Specify package capability for a new package
package example.com/some/package CAPABILITY_OPERATING_SYSTEM
# Specify package capability for a new function
func example.com/some/package.Foo CAPABILITY_FILES
# Override existing function capability
func fmt.Sprintf CAPABILITY_FILES
`
)


func TestInteresting(t *testing.T) {
	classifier := DefaultClassifier()
	for _, c := range []struct {
		pkg, fn string
		want    cpb.Capability
	}{
		{
			"os",
			"os.Open",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"fmt",
			"fmt.Sprintf",
			cpb.Capability_CAPABILITY_SAFE,
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			cpb.Capability_CAPABILITY_UNSPECIFIED,
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo_Cfunc_GoString",
			cpb.Capability_CAPABILITY_CGO,
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			cpb.Capability_CAPABILITY_OPERATING_SYSTEM,
		},
		{
			"runtime",
			"runtime.SomeOtherFunctionWithNoFunctionLevelCategoryYet",
			cpb.Capability_CAPABILITY_RUNTIME,
		},
		{
			"runtime",
			"(*runtime.Func).Name",
			cpb.Capability_CAPABILITY_SAFE,
		},
		{
			"foo",
			"foo.Something_Cfunc_GoString",
			cpb.Capability_CAPABILITY_CGO,
		},
		{
			"foo",
			"foo.Something",
			cpb.Capability_CAPABILITY_UNSPECIFIED,
		},
	} {
		if got := classifier.FunctionCategory(c.pkg, c.fn); got != c.want {
			t.Errorf("FunctionCategory(%q, %q): got %q, want %q", c.pkg, c.fn, got, c.want)
		}
	}
}

func TestUserWithBuiltin(t *testing.T) {
	classifier, err := LoadClassifier(t.Name(), strings.NewReader(userCapabilityMap), false)
	if err != nil {
		t.Fatalf("LoadClassifier failed: %v", err)
	}
	for _, c := range []struct {
		pkg, fn string
		want    cpb.Capability
	}{
		{
			"os",
			"os.Open",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			cpb.Capability_CAPABILITY_OPERATING_SYSTEM,
		},
		{
			"fmt",
			"fmt.Sprintf",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"example.com/some/package",
			"example.com/some/package.OtherFoo",
			cpb.Capability_CAPABILITY_OPERATING_SYSTEM,
		},
		{
			"runtime",
			"runtime.SomeFunction",
			cpb.Capability_CAPABILITY_NETWORK,
		},
	} {
		if got := classifier.FunctionCategory(c.pkg, c.fn); got != c.want {
			t.Errorf("FunctionCategory(%q, %q): got %q, want %q", c.pkg, c.fn, got, c.want)
		}
	}
}

func TestUserWithoutBuiltin(t *testing.T) {
	classifier, err := LoadClassifier(t.Name(), strings.NewReader(userCapabilityMap), true)
	if err != nil {
		t.Fatalf("LoadClassifier failed: %v", err)
	}
	for _, c := range []struct {
		pkg, fn string
		want    cpb.Capability
	}{
		{
			"os",
			"os.Open",
			cpb.Capability_CAPABILITY_UNSPECIFIED,
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			cpb.Capability_CAPABILITY_UNSPECIFIED,
		},
		{
			"fmt",
			"fmt.Sprintf",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			cpb.Capability_CAPABILITY_FILES,
		},
		{
			"example.com/some/package",
			"example.com/some/package.OtherFoo",
			cpb.Capability_CAPABILITY_OPERATING_SYSTEM,
		},
		{
			"runtime",
			"runtime.SomeFunction",
			cpb.Capability_CAPABILITY_NETWORK,
		},
	} {
		if got := classifier.FunctionCategory(c.pkg, c.fn); got != c.want {
			t.Errorf("FunctionCategory(%q, %q): got %q, want %q", c.pkg, c.fn, got, c.want)
		}
	}
}
