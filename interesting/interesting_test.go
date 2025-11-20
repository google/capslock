// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package interesting

import (
	"strings"
	"testing"
)

const (
	userCapabilityMap = `
# Override existing package capability
package runtime CAPABILITY_NETWORK
# Specify package capability for a new package
package example.com/some/package CAPABILITY_OPERATING_SYSTEM
# Specify package capability for a new function
func example.com/some/package.Foo MODIFY_SYSTEM_STATE/ENV
# Override existing function capability
func fmt.Sprintf CAPABILITY_FILES
`
)

func TestInteresting(t *testing.T) {
	classifier := DefaultClassifier()
	for _, c := range []struct {
		pkg, fn string
		want    string
	}{
		{
			"os",
			"os.Open",
			"FILES",
		},
		{
			"fmt",
			"fmt.Sprintf",
			"SAFE",
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			"",
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo_Cfunc_GoString",
			"CGO",
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			"OPERATING_SYSTEM",
		},
		{
			"runtime",
			"runtime.SomeOtherFunctionWithNoFunctionLevelCategoryYet",
			"RUNTIME",
		},
		{
			"runtime",
			"(*runtime.Func).Name",
			"SAFE",
		},
		{
			"foo",
			"foo.Something_Cfunc_GoString",
			"CGO",
		},
		{
			"foo",
			"foo.Something",
			"",
		},
		{
			"os",
			"os.Setenv",
			"MODIFY_SYSTEM_STATE/ENV",
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
		want    string
	}{
		{
			"os",
			"os.Open",
			"FILES",
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			"OPERATING_SYSTEM",
		},
		{
			"fmt",
			"fmt.Sprintf",
			"FILES",
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			"MODIFY_SYSTEM_STATE/ENV",
		},
		{
			"example.com/some/package",
			"example.com/some/package.OtherFoo",
			"OPERATING_SYSTEM",
		},
		{
			"runtime",
			"runtime.SomeFunction",
			"NETWORK",
		},
		{
			"os",
			"os.Setenv",
			"MODIFY_SYSTEM_STATE/ENV",
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
		want    string
	}{
		{
			"os",
			"os.Open",
			"",
		},
		{
			"os",
			"os.SomeNewFunctionWithNoFunctionLevelCategoryYet",
			"",
		},
		{
			"fmt",
			"fmt.Sprintf",
			"FILES",
		},
		{
			"example.com/some/package",
			"example.com/some/package.Foo",
			"MODIFY_SYSTEM_STATE/ENV",
		},
		{
			"example.com/some/package",
			"example.com/some/package.OtherFoo",
			"OPERATING_SYSTEM",
		},
		{
			"runtime",
			"runtime.SomeFunction",
			"NETWORK",
		},
		{
			"os",
			"os.Setenv",
			"",
		},
	} {
		if got := classifier.FunctionCategory(c.pkg, c.fn); got != c.want {
			t.Errorf("FunctionCategory(%q, %q): got %q, want %q", c.pkg, c.fn, got, c.want)
		}
	}
}
