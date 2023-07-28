// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package interesting

import (
	"testing"

	cpb "capslock/proto"
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
	} {
		if got := classifier.FunctionCategory(c.pkg, c.fn); got != c.want {
			t.Errorf("FunctionCategory(%q, %q): got %q, want %q", c.pkg, c.fn, got, c.want)
		}
	}
}
