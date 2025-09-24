// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzepackages_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"

	cpb "github.com/google/capslock/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

var bin string // temporary file containing the capslock executable

func TestMain(m *testing.M) {
	// Compile capslock once.
	f, err := os.CreateTemp("", "capslock*.exe")
	if err != nil {
		log.Fatal("Creating temporary file: ", err)
	}
	bin = f.Name()
	if err = f.Close(); err != nil {
		log.Fatal("Closing temporary file: ", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "../cmd/capslock")
	if err = cmd.Run(); err != nil {
		log.Fatal("Building executable: ", err)
	}
	// Run tests.
	m.Run()
	os.Remove(bin)
}

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
		if len(path.Cap) != 0 && ci.GetCapabilityName() != path.Cap {
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

var analyzeResult struct {
	sync.Once
	output []byte
	error
}

// analyze returns the results of analyzing the test packages with
// capslock -output=json.  It caches its results in analyzeResult.
func analyze() ([]byte, error) {
	analyzeResult.Do(func() {
		cmd := exec.Command(bin, "-packages=../testpkgs/...", "-output=json")
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			analyzeResult.error = fmt.Errorf("running capslock: %w", err)
			return
		}
		analyzeResult.output = output.Bytes()
	})
	return analyzeResult.output, analyzeResult.error
}

func TestExpectedOutput(t *testing.T) {
	analyzeOutput, err := analyze()
	if err != nil {
		t.Fatal(err)
	}
	cil := new(cpb.CapabilityInfoList)
	if err = protojson.Unmarshal(analyzeOutput, cil); err != nil {
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
		{Fn: []string{"initfn.init"}, Cap: "REFLECT"},
		{Fn: []string{"initfn.init"}, Cap: "UNSAFE_POINTER"},
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
		{Fn: []string{"transitive.InterestingOnceDo$"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingOnceDo2$"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingOnceDo3$"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.OnceInStruct$"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.ComplicatedExpressionWithOnce$"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSort"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortViaFunction", "sort.Sort"}, Cap: "UNANALYZED"},
		{Fn: []string{"transitive.InterestingSortSlice"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortSliceNested"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSortSliceStable"}, Cap: "READ_SYSTEM_STATE"},
		{Fn: []string{"transitive.InterestingSyncPool"}, Cap: "UNANALYZED"},
		{Fn: []string{"transitive.Linkname", "uselinkname.Foo", "uselinkname.runtime_fastrand64"}, Cap: "ARBITRARY_EXECUTION"},
		{Fn: []string{"transitive.MultipleCapabilities", "usecgo._cgo_runtime_cgocall"}},
		{Fn: []string{"transitive.MultipleCapabilities", "os.Getpid"}},
		{Fn: []string{"transitive.Net", "net.LookupIP"}},
		{Fn: []string{"transitive.Os", "os.Getpid"}},
		{Fn: []string{"transitive.UninterestingSyncPool"}, Cap: "UNANALYZED"},
		{Fn: []string{"transitive.Unsafe"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{`transitive.UseBigIntRand`, `big.Int..Rand`, `transitive.src..Int63`, `net.LookupIP`}},
		{Fn: []string{"transitive.init", "initfn.init"}, Cap: "REFLECT"},
		{Fn: []string{"transitive.init", "initfn.init"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{"transitive.init", "initfn.init", "net.LookupIP"}},
		{Fn: []string{"transitive.init", "initfn.init", "os.Getpid"}},
		{Fn: []string{"transitive.init", "initfn.init", "runtime/debug.SetMaxThreads"}},
		{Fn: []string{"useasm.Foo", "useasm.bar"}},
		{Fn: []string{"useasm.bar"}, Cap: "ARBITRARY_EXECUTION"},
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
		{Fn: []string{"uselinkname.CallExplicitlyCategorizedFunction", "syscall.Getpagesize"}, Cap: "SYSTEM_CALLS"},
		{Fn: []string{"uselinkname.Foo", "uselinkname.runtime_fastrand64"}, Cap: "ARBITRARY_EXECUTION"},
		{Fn: []string{"uselinkname.runtime_fastrand64"}, Cap: "ARBITRARY_EXECUTION"},
		{Fn: []string{`usereflect.CopyValueConcurrently\$1`}, Cap: `REFLECT`},
		{Fn: []string{`usereflect.CopyValueConcurrently\$2`}, Cap: `REFLECT`},
		{Fn: []string{`usereflect.CopyValueConcurrently`, `usereflect.CopyValueConcurrently\$[12]`}},
		{Fn: []string{"usereflect.CopyValueContainingStructAlias2$"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueContainingStructAliasViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueContainingStructViaPointer$"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueEquivalentViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueGlobal"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueInArrayViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueInMultipleAssignmentViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueInStructFieldViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{"usereflect.CopyValueViaPointer"}, Cap: "REFLECT"},
		{Fn: []string{`usereflect.RangeValueTwo\$1`}, Cap: `REFLECT`},
		{Fn: []string{`usereflect.RangeValueTwo\$2`}, Cap: `REFLECT`},
		{Fn: []string{`usereflect.RangeValueTwo`, `usereflect.RangeValueTwo\$[12]`}},
		{Fn: []string{"useunsafe.Bar"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{"useunsafe.Baz"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.CallNestedFunctions`, `useunsafe.NestedFunctions\$1\$1\$1`}},
		{Fn: []string{"useunsafe.Foo"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.Indirect`, `useunsafe.ReturnFunction\$1`}},
		{Fn: []string{`useunsafe.Indirect2`, `useunsafe.init\$1`}},
		{Fn: []string{`useunsafe.NestedFunctions\$1\$1\$1`}, Cap: `UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.ReturnFunction\$1`}, Cap: `UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.T\).M`}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{`useunsafe.init$`}, Cap: `UNSAFE_POINTER`},
		{Fn: []string{`useunsafe.init\$1`}, Cap: `UNSAFE_POINTER`},
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
		{Fn: []string{"usegenerics.Foo"}, Cap: "ARBITRARY_EXECUTION"},
		{Fn: []string{"uselinkname.CallExplicitlyCategorizedFunction", "syscall.Getpagesize"}, Cap: "ARBITRARY_EXECUTION"},
		{Fn: []string{"useunsafe.Ok"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{"useunsafe.ReturnFunction$"}, Cap: "UNSAFE_POINTER"},
		{Fn: []string{"usegenerics.AtomicPointer"}},

		// Currently we don't include functions called by these functions.
		{Fn: []string{"^sort.Sort", ".*"}}, // need ^ to avoid matching notsort.go
		{Fn: []string{"sort.Slice", ".*"}},
		{Fn: []string{`\(\*sync.Once\).Do`, ".*"}},
		{Fn: []string{`\(\*sync.Pool\).Get`, ".*"}},

		// We do not expect the following call paths, as they are avoided by the
		// syntax-tree-rewriting code.
		{Fn: []string{`transitive.InterestingOnceDo$`, `\(\*sync.Once\).Do`}},
		{Fn: []string{`transitive.InterestingOnceDo2$`, `\(\*sync.Once\).Do`}},
		{Fn: []string{`transitive.InterestingOnceDo3$`, `\(\*sync.Once\).Do`}},
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
		{Fn: []string{"usereflect.CopyValueContainingStructAlias$"}},
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
		t.Log(string(analyzeOutput))
	}
}

func TestGraph(t *testing.T) {
	for _, test := range []struct {
		args      []string
		wantLines map[string]int
	}{
		{
			[]string{"-packages=../testpkgs/useunsafe", "-output=graph"},
			map[string]int{
				`digraph {`: 0,
				`"github.com/google/capslock/testpkgs/useunsafe.Bar" -> "UNSAFE_POINTER"`:                                                                      0,
				`"github.com/google/capslock/testpkgs/useunsafe.Baz" -> "UNSAFE_POINTER"`:                                                                      0,
				`"github.com/google/capslock/testpkgs/useunsafe.CallNestedFunctions" -> "github.com/google/capslock/testpkgs/useunsafe.NestedFunctions$1$1$1"`: 0,
				`"github.com/google/capslock/testpkgs/useunsafe.Foo" -> "UNSAFE_POINTER"`:                                                                      0,
				`"github.com/google/capslock/testpkgs/useunsafe.Indirect2" -> "github.com/google/capslock/testpkgs/useunsafe.init$1"`:                          0,
				`"github.com/google/capslock/testpkgs/useunsafe.Indirect" -> "github.com/google/capslock/testpkgs/useunsafe.ReturnFunction$1"`:                 0,
				`"github.com/google/capslock/testpkgs/useunsafe.init$1" -> "UNSAFE_POINTER"`:                                                                   0,
				`"github.com/google/capslock/testpkgs/useunsafe.init" -> "UNSAFE_POINTER"`:                                                                     0,
				`"github.com/google/capslock/testpkgs/useunsafe.NestedFunctions$1$1$1" -> "UNSAFE_POINTER"`:                                                    0,
				`"github.com/google/capslock/testpkgs/useunsafe.ReturnFunction$1" -> "UNSAFE_POINTER"`:                                                         0,
				`"(github.com/google/capslock/testpkgs/useunsafe.T).M" -> "UNSAFE_POINTER"`:                                                                    0,
				`}`: 0,
			},
		},
		{
			[]string{"-packages=../testpkgs/callos", "-output=graph", "-capabilities=READ_SYSTEM_STATE,NETWORK,MODIFY_SYSTEM_STATE/ENV"},
			map[string]int{
				`digraph {`: 0,
				`"github.com/google/capslock/testpkgs/callos.Baz" -> "os/user.Current"`: 0,
				`"github.com/google/capslock/testpkgs/callos.Foo" -> "os.Getpid"`:       0,
				`"github.com/google/capslock/testpkgs/callos.Setenv" -> "os.Setenv"`:    0,
				`"os/user.Current" -> "READ_SYSTEM_STATE"`:                              0,
				`"os.Getpid" -> "READ_SYSTEM_STATE"`:                                    0,
				`"os.Setenv" -> "MODIFY_SYSTEM_STATE/ENV"`:                              0,
				`}`: 0,
			},
		},
		{
			[]string{"-packages=../testpkgs/callos", "-output=graph", "-capabilities=-FILES,-READ_SYSTEM_STATE"},
			map[string]int{
				`digraph {`: 0,
				`"github.com/google/capslock/testpkgs/callos.Bar" -> "os/exec.Command"`:    0,
				`"github.com/google/capslock/testpkgs/callos.Bar" -> "(*os/exec.Cmd).Run"`: 0,
				`"github.com/google/capslock/testpkgs/callos.Setenv" -> "os.Setenv"`:       0,
				`"os/exec.Command" -> "EXEC"`:                                              0,
				`"(*os/exec.Cmd).Run" -> "EXEC"`:                                           0,
				`"os.Setenv" -> "MODIFY_SYSTEM_STATE/ENV"`:                                 0,
				`}`: 0,
			},
		},
		{
			[]string{"-packages=../testpkgs/callutf8", "-output=graph"},
			map[string]int{
				`digraph {`: 0,
				`}`:         0,
			},
		},
	} {
		cmd := exec.Command(bin, test.args...)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Errorf("running capslock with arguments %q: %v.  stdout:", test.args, err)
			if _, err := os.Stderr.Write(output.Bytes()); err != nil {
				t.Errorf("couldn't write capslock's output to stderr: %v", err)
			}
			t.Fatalf("failed to run capslock with arguments %q.", test.args)
		}
		gotLines := make(map[string]int)
		failed := false
		for _, s := range strings.Split(output.String(), "\n") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := test.wantLines[s]; !ok {
				t.Errorf("TestGraph(%q): saw unexpected output line %q", test.args, s)
				failed = true
				continue
			}
			gotLines[s]++
		}
		for s := range test.wantLines {
			if c := gotLines[s]; c != 1 {
				t.Errorf("TestGraph(%q): got output line %q %d times, want 1", test.args, s, c)
				failed = true
			}
		}
		if failed {
			t.Log(output.String())
		}
	}
}

func TestCompare(t *testing.T) {
	mktemp := func(contents []byte) (name string, err error, done func()) {
		f, err := os.CreateTemp("", "capslock-test-*.json")
		if err != nil {
			return "", err, nil
		}
		if _, err = f.Write(contents); err != nil {
			return "", err, nil
		}
		return f.Name(), nil, func() {
			name := f.Name()
			f.Close()
			os.Remove(name)
		}
	}

	// Make a temporary file with the expected output.
	b, err := analyze()
	if err != nil {
		t.Fatal(err)
	}
	f1, err, done := mktemp(b)
	if err != nil {
		t.Fatalf("Creating first temporary file: %v", err)
	}
	defer done()

	// Make a second temporary file with some of the output changed, to produce
	// a difference to be found.
	b = bytes.ReplaceAll(b, []byte("callruntime"), []byte("callruntime2"))
	b = bytes.ReplaceAll(b, []byte("callos"), []byte("callos2"))
	f2, err, done := mktemp(b)
	if err != nil {
		t.Fatalf("Creating second temporary file: %v", err)
	}
	defer done()

	for _, test := range []struct {
		diffFile         string
		granularity      string
		expectedExitCode int
		expectedOutput   []string
	}{
		{f1, "package", 0, nil},
		{f1, "function", 0, nil},
		{f2, "package", 1, []string{
			"callruntime has new capability RUNTIME",
			"callruntime2 no longer has capability RUNTIME",
			"callos has new capability MODIFY_SYSTEM_STATE/ENV",
			"callos2 no longer has capability MODIFY_SYSTEM_STATE/ENV",
		}},
		{f2, "function", 1, []string{
			"callruntime.Interesting has new capability RUNTIME",
			"callruntime2.Interesting no longer has capability RUNTIME",
			"callos.Setenv has new capability MODIFY_SYSTEM_STATE/ENV",
			"callos2.Setenv no longer has capability MODIFY_SYSTEM_STATE/ENV",
		}},
		{"../testpkgs/notthere", "package", 2, nil},
	} {
		cmd := exec.Command(bin, "-packages=../testpkgs/...", "-granularity="+test.granularity, "-output=compare", test.diffFile)
		var output bytes.Buffer
		cmd.Stdout = &output
		err := cmd.Run()
		// Check the exit status.
		switch err := err.(type) {
		case nil:
			if got, want := 0, test.expectedExitCode; got != want {
				t.Errorf("%v: got exit code %d, want %d", test, got, want)
			}
		case *exec.ExitError:
			if got, want := err.ExitCode(), test.expectedExitCode; got != want {
				t.Errorf("%v: got exit code %d, want %d", test, got, want)
			}
		default:
			t.Errorf("%v: running capslock: %v", test, err)
		}
		if t.Failed() {
			continue
		}
		// Check that any expected lines are present in the diff output.
		lines := strings.Split(output.String(), "\n")
		for _, expected := range test.expectedOutput {
			ok := false
			for _, line := range lines {
				if matches, err := regexp.MatchString(expected, line); matches {
					ok = true
				} else if err != nil {
					t.Errorf("parsing expression %q: %v", expected, err)
				}
			}
			if !ok {
				t.Errorf("%v: expected output line %q", test, expected)
			}
		}
	}
}

func TestVersionFlag(t *testing.T) {
	out, err := exec.Command(bin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("running capslock: error %v output %q", err, string(out))
	}
	if s, want := string(out), "capslock version"; !strings.HasPrefix(s, want) {
		t.Errorf("got %q, want prefix %q", s, want)
	}
}
