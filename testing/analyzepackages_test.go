// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzepackages_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	cpb "github.com/google/capslock/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

type expectedPath struct {
	Fn  []string
	Cap string
}

// matches returns true if for one of the CapabilityInfo objects in the input:
//
//   - The object's path contains functions which match each of the elements of
//     path.Fn.  The matching functions do not have to be consecutive, but they
//     do need to be in order.
//
// - path.Cap is either empty, or matches the capability in the CapabilityInfo.
func (path expectedPath) matches(cil *cpb.CapabilityInfoList) (bool, error) {
	if len(path.Fn) == 0 {
		return false, fmt.Errorf("empty path")
	}
	for _, ci := range cil.GetCapabilityInfo() {
		if len(path.Cap) != 0 && ci.GetCapability().String() != path.Cap {
			continue
		}
		i := 0
		for _, f := range ci.GetPath() {
			if matches, err := regexp.MatchString(path.Fn[i], f.GetName()); matches {
				i++
				if i == len(path.Fn) {
					return true, nil
				}
			} else if err != nil {
				return false, fmt.Errorf("parsing expression %q: %v", path.Fn[i], err)
			}
		}
	}
	return false, nil
}

func TestExpectedOutput(t *testing.T) {
	// Run analyzepackages, get its stdout in output.
	cmd := exec.Command(
		"go", "run", "../cmd/capslock", "-packages=../testpkgs/...", "-output=json")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("exec.Command.Run: %v.  stdout:", err)
		if _, err := os.Stderr.Write(output.Bytes()); err != nil {
			t.Errorf("couldn't write analyzepackages' output to stderr: %v", err)
		}
		t.Fatalf("failed to run analyzepackages.")
	}

	cil := new(cpb.CapabilityInfoList)
	err := protojson.Unmarshal(output.Bytes(), cil)
	if err != nil {
		t.Fatalf("Couldn't parse analyzer output: %v", err)
	}

	expectedPaths := []expectedPath{
		{Fn: []string{"buildtags.Foo", "net.LookupIP"}},
		{Fn: []string{"callnet.Foo", "net.LookupIP"}},
		{Fn: []string{"callos.Foo", "os.Getpid"}},
		{Fn: []string{"callos.Bar", "os/exec"}},
		{Fn: []string{"callos.Baz", "os/user.Current"}},
		{Fn: []string{"callruntime.Interesting", "runtime.CPUProfile"}},
		{Fn: []string{"importname.CallTheWrongSort", "os.ReadFile"}},
		{Fn: []string{`indirectcalls.AccessMethodViaTypeAssertion`, `\(\*os.File\).Chown`}},
		{Fn: []string{"indirectcalls.CallOs", "os.Getuid"}},
		{Fn: []string{"indirectcalls.CallOsViaFuncVariable", "os.Getuid"}},
		{Fn: []string{"indirectcalls.CallOsViaInterfaceMethod", "os.Getuid"}},
		{Fn: []string{"indirectcalls.CallOsViaStructField", "os.Getuid"}},
		{Fn: []string{`indirectcalls.myStruct\).foo`, `os.Getuid`}},
		{Fn: []string{"initfn.init"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"initfn.init"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{"initfn.init", "net.LookupIP"}},
		{Fn: []string{"initfn.init", "os.Getpid"}},
		{Fn: []string{"initfn.init", "runtime/debug.SetMaxThreads"}},
		{Fn: []string{"transitive.Asm", "useasm.Foo", "useasm.bar"}},
		{Fn: []string{`transitive.CallGenericFunction`, `usegenerics.Foo\[.*/transitive.a\]`, `\(.*/transitive.a\).Baz`, `net.Dial`}},
		{Fn: []string{`transitive.CallGenericFunction`, `usegenerics.Foo\[.*/transitive.a\]`, `os.Rename`}},
		{Fn: []string{`transitive.CallGenericFunctionTransitively`, `usegenerics.Bar`, `usegenerics.Foo\[.*/usegenerics.a\]`, `\(.*/usegenerics.a\).Baz`, `net.Interfaces`}},
		{Fn: []string{`transitive.CallGenericFunctionTransitively`, `usegenerics.Bar`, `usegenerics.Foo\[.*/usegenerics.a\]`, `os.Rename`}},
		{Fn: []string{"transitive.CallViaStdlib", "callnet.Foo", "net.LookupIP"}},
		{Fn: []string{"transitive.Cgo", "usecgo._cgo_runtime_cgocall"}},
		{Fn: []string{"transitive.Indirect", "os.Getuid"}},
		{Fn: []string{"transitive.InterestingOnceDo"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.OnceInStruct"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.ComplicatedExpressionWithOnce"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSort"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortViaFunction", "sort.Sort"}, Cap: "CAPABILITY_UNANALYZED"},
		{Fn: []string{"transitive.InterestingSortSlice"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortSliceNested"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortSliceStable"}, Cap: "CAPABILITY_READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSyncPool"}, Cap: "CAPABILITY_UNANALYZED"},
		{Fn: []string{"transitive.Linkname", "uselinkname.Foo", "uselinkname.runtime_fastrand64"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{"transitive.MultipleCapabilities", "usecgo._cgo_runtime_cgocall"}},
		{Fn: []string{"transitive.MultipleCapabilities", "os.Getpid"}},
		{Fn: []string{"transitive.Net", "net.LookupIP"}},
		{Fn: []string{"transitive.Os", "os.Getpid"}},
		{Fn: []string{"transitive.UninterestingSyncPool"}, Cap: "CAPABILITY_UNANALYZED"},
		{Fn: []string{"transitive.Unsafe"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{`transitive.UseBigIntRand`, `big.Int..Rand`, `transitive.src..Int63`, `net.LookupIP`}},
		{Fn: []string{"transitive.init", "initfn.init"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"transitive.init", "initfn.init"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{"transitive.init", "initfn.init", "net.LookupIP"}},
		{Fn: []string{"transitive.init", "initfn.init", "os.Getpid"}},
		{Fn: []string{"transitive.init", "initfn.init", "runtime/debug.SetMaxThreads"}},
		{Fn: []string{"useasm.Foo", "useasm.bar"}},
		{Fn: []string{"useasm.bar"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{"usecgo.CallCBytes", ""}},
		{Fn: []string{"usecgo.CallCString", ""}},
		{Fn: []string{"usecgo.CallGoBytes", ""}},
		{Fn: []string{"usecgo.CallGoString", ""}},
		{Fn: []string{"usecgo.CallGoStringN", ""}},
		{Fn: []string{"usecgo.Foo", "usecgo._cgo_runtime_cgocall"}},
		{Fn: []string{"usecgo._Cfunc_acfunction", "usecgo._cgo_runtime_cgocall"}},
		{Fn: []string{`usegenerics.Bar`, `usegenerics.Foo\[.*/usegenerics.a\]`, `\(.*/usegenerics.a\).Baz`, `net.Interfaces`}},
		{Fn: []string{`usegenerics.Bar`, `usegenerics.Foo\[.*/usegenerics.a\]`, `os.Rename`}},
		{Fn: []string{`usegenerics.a\).Baz`, `net.Interfaces`}},
		{Fn: []string{`usegenerics.CallNestedFunction`, `usegenerics.NestedFunction\[.*/usegenerics.a\]\$1`, `\(.*/usegenerics.a\).Baz`, `net.Interfaces`}},
		{Fn: []string{"uselinkname.CallExplicitlyCategorizedFunction", "syscall.Getpagesize"}, Cap: "CAPABILITY_SYSTEM_CALLS"},
		{Fn: []string{"uselinkname.Foo", "uselinkname.runtime_fastrand64"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{"uselinkname.runtime_fastrand64"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{`usereflect.CopyValueConcurrently\$1`}, Cap: `CAPABILITY_REFLECT`},
		{Fn: []string{`usereflect.CopyValueConcurrently\$2`}, Cap: `CAPABILITY_REFLECT`},
		{Fn: []string{`usereflect.CopyValueConcurrently`, `usereflect.CopyValueConcurrently\$[12]`}},
		{Fn: []string{"usereflect.CopyValueContainingStructViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueEquivalentViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueGlobal"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueInArrayViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueInMultipleAssignmentViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueInStructFieldViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{"usereflect.CopyValueViaPointer"}, Cap: "CAPABILITY_REFLECT"},
		{Fn: []string{`usereflect.RangeValueTwo\$1`}, Cap: `CAPABILITY_REFLECT`},
		{Fn: []string{`usereflect.RangeValueTwo\$2`}, Cap: `CAPABILITY_REFLECT`},
		{Fn: []string{`usereflect.RangeValueTwo`, `usereflect.RangeValueTwo\$[12]`}},
		{Fn: []string{"useunsafe.Bar"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{"useunsafe.Baz"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.CallNestedFunctions`, `useunsafe.NestedFunctions\$1\$1\$1`}},
		{Fn: []string{"useunsafe.Foo"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.Indirect`, `useunsafe.ReturnFunction\$1`}},
		{Fn: []string{`useunsafe.Indirect2`, `useunsafe.init\$1`}},
		{Fn: []string{`useunsafe.NestedFunctions\$1\$1\$1`}, Cap: `CAPABILITY_UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.ReturnFunction\$1`}, Cap: `CAPABILITY_UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.T\).M`}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.init$`}, Cap: `CAPABILITY_UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.init\$1`}, Cap: `CAPABILITY_UNSAFE_POINTER`},
	}
	for _, path := range expectedPaths {
		if matches, err := path.matches(cil); err != nil {
			t.Fatalf("TestExpectedOutput: internal error: %v", err)
		} else if !matches {
			t.Errorf("TestExpectedOutput: did not find expected path %v", path)
		}
	}
	unexpectedPaths := []expectedPath{
		{Fn: []string{"indirectcalls.ShouldHaveNoCapabilities"}},
		{Fn: []string{"callos.init"}},
		{Fn: []string{"callruntime.Uninteresting"}},
		{Fn: []string{"transitive.AllowedAsmInStdlib"}},
		{Fn: []string{"usegenerics.Foo"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{"uselinkname.CallExplicitlyCategorizedFunction", "syscall.Getpagesize"}, Cap: "CAPABILITY_ARBITRARY_EXECUTION"},
		{Fn: []string{"useunsafe.Ok"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{"useunsafe.ReturnFunction$"}, Cap: "CAPABILITY_UNSAFE_POINTER"},
		{Fn: []string{"usegenerics.AtomicPointer"}},

		// Currently we don't include functions called by these functions.
		{Fn: []string{"^sort.Sort", ".*"}}, // need ^ to avoid matching notsort.go
		{Fn: []string{"sort.Slice", ".*"}},
		{Fn: []string{`\(\*sync.Once\).Do`, ".*"}},
		{Fn: []string{`\(\*sync.Pool\).Get`, ".*"}},

		// We do not expect the following call paths, as they are avoided by the
		// syntax-tree-rewriting code.
		{Fn: []string{`transitive.InterestingOnceDo`, `\(\*sync.Once\).Do`}},
		{Fn: []string{`transitive.OnceInStruct`, `\(\*sync.Once\).Do`}},
		{Fn: []string{`transitive.ComplicatedExpressionWithOnce`, `\(\*sync.Once\).Do`}},
		{Fn: []string{"transitive.UninterestingOnceDo", ".*"}},
		{Fn: []string{"transitive.UninterestingSort", ".*"}},
		{Fn: []string{"transitive.UninterestingSortSlice", ".*"}},
		{Fn: []string{"transitive.UninterestingSortSliceNested", ".*"}},
		{Fn: []string{"transitive.UninterestingSortSliceStable", ".*"}},

		// These functions copy reflect.Value objects, but the destinations are
		// only local variables which do not escape, so we do not need to warn
		// about them.
		{Fn: []string{"usereflect.CopyValue$"}},
		{Fn: []string{"usereflect.CopyValueContainingStruct$"}},
		{Fn: []string{"usereflect.CopyValueEquivalent$"}},
		{Fn: []string{"usereflect.CopyValueInArray$"}},
		{Fn: []string{"usereflect.CopyValueInCommaOk"}},
		{Fn: []string{"usereflect.CopyValueInMultipleAssignment$"}},
		{Fn: []string{"usereflect.CopyValueInStructField$"}},
		{Fn: []string{"usereflect.RangeValue$"}},

		// MaybeChmod type-asserts an io.Reader parameter to an interface whose
		// method set contains Chmod, so that (*os.File).Chmod can be called if
		// the user passes an argument with dynamic type *os.File.  No code in
		// our testdata does this, so we do not warn about this code having an
		// interesting capability, but perhaps it would be good to do so.
		{Fn: []string{`indirectcalls.MaybeChmod`, `\(*os.File\).Chmod`}},
	}
	for _, path := range unexpectedPaths {
		if matches, err := path.matches(cil); err != nil {
			t.Fatalf("TestExpectedOutput: internal error: %v", err)
		} else if matches {
			t.Errorf("TestExpectedOutput: expected not to see match for %v", path)
		}
	}
	if t.Failed() {
		t.Log(output.String())
	}
}

func TestGraph(t *testing.T) {
	// Run analyzepackages, get its stdout in output.
	cmd := exec.Command(
		"go", "run", "../cmd/capslock", "-packages=../testpkgs/useunsafe", "-output=graph")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("exec.Command.Run: %v.  stdout:", err)
		if _, err := os.Stderr.Write(output.Bytes()); err != nil {
			t.Errorf("couldn't write analyzepackages' output to stderr: %v", err)
		}
		t.Fatalf("failed to run analyzepackages.")
	}
	// map from expected strings to the number of times each is seen in the output.
	m := map[string]int{
		`digraph {`: 0,
		`"github.com/google/capslock/testpkgs/useunsafe.Bar" -> "CAPABILITY_UNSAFE_POINTER"`:                                                           0,
		`"github.com/google/capslock/testpkgs/useunsafe.Baz" -> "CAPABILITY_UNSAFE_POINTER"`:                                                           0,
		`"github.com/google/capslock/testpkgs/useunsafe.CallNestedFunctions" -> "github.com/google/capslock/testpkgs/useunsafe.NestedFunctions$1$1$1"`: 0,
		`"github.com/google/capslock/testpkgs/useunsafe.Foo" -> "CAPABILITY_UNSAFE_POINTER"`:                                                           0,
		`"github.com/google/capslock/testpkgs/useunsafe.Indirect2" -> "github.com/google/capslock/testpkgs/useunsafe.init$1"`:                          0,
		`"github.com/google/capslock/testpkgs/useunsafe.Indirect" -> "github.com/google/capslock/testpkgs/useunsafe.ReturnFunction$1"`:                 0,
		`"github.com/google/capslock/testpkgs/useunsafe.init$1" -> "CAPABILITY_UNSAFE_POINTER"`:                                                        0,
		`"github.com/google/capslock/testpkgs/useunsafe.init" -> "CAPABILITY_UNSAFE_POINTER"`:                                                          0,
		`"github.com/google/capslock/testpkgs/useunsafe.NestedFunctions$1$1$1" -> "CAPABILITY_UNSAFE_POINTER"`:                                         0,
		`"github.com/google/capslock/testpkgs/useunsafe.ReturnFunction$1" -> "CAPABILITY_UNSAFE_POINTER"`:                                              0,
		`"(github.com/google/capslock/testpkgs/useunsafe.T).M" -> "CAPABILITY_UNSAFE_POINTER"`:                                                         0,
		`}`: 0,
	}
	for _, s := range strings.Split(output.String(), "\n") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := m[s]; !ok {
			t.Errorf("TestGraph: saw unexpected output line %q", s)
			continue
		}
		m[s]++
	}
	for s, c := range m {
		if c != 1 {
			t.Errorf("TestGraph: got output line %q %d times, want 1", s, c)
		}
	}
	if t.Failed() {
		t.Log(output.String())
	}
}
