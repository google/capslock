// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package transitive is used for testing.
package transitive

import (
	"bytes"
	"math/big"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/google/capslock/testpkgs/callnet"
	"github.com/google/capslock/testpkgs/callos"
	"github.com/google/capslock/testpkgs/callutf8"
	"github.com/google/capslock/testpkgs/indirectcalls"
	_ "github.com/google/capslock/testpkgs/initfn" // for testing
	"github.com/google/capslock/testpkgs/useasm"
	"github.com/google/capslock/testpkgs/usecgo"
	"github.com/google/capslock/testpkgs/usegenerics"
	"github.com/google/capslock/testpkgs/uselinkname"
	"github.com/google/capslock/testpkgs/useunsafe"
)

// MultipleCapabilities transitively calls a function in os, and a cgo function.
func MultipleCapabilities() int {
	return Os() + Cgo()
}

// Net transitively calls a function in net.
func Net() int {
	return callnet.Foo() + 1
}

// Os transitively calls a function in os.
func Os() int {
	return callos.Foo() + 1
}

// Unsafe calls a function which uses an unsafe pointer.
func Unsafe() int {
	return useunsafe.Foo() + 1
}

// Utf8 transitively calls a function in unicode/utf8.
func Utf8() int {
	return callutf8.Foo() + 1
}

// Cgo transitively calls a cgo function.
func Cgo() int {
	return usecgo.Foo() + 1
}

// Indirect transitively calls a function in os via an interface method call.
func Indirect() int {
	return indirectcalls.CallOsViaInterfaceMethod() + 1
}

// InterestingOnceDo calls Do on a sync.Once.  The function passed to Do calls
// an interesting function in the os package.
func InterestingOnceDo() int {
	var once sync.Once
	once.Do(func() { callos.Foo() })
	return 12345
}

type structContainingOnce struct {
	a int
	b sync.Once
	c int
}

// OnceInStruct calls Do on a sync.Once in a struct field.
func OnceInStruct() int {
	var a structContainingOnce
	a.b.Do(func() { callos.Foo() })
	return 12345
}

// ComplicatedExpressionWithOnce calls Do on a sync.Once using a complicated
// but side-effect-free expression.
func ComplicatedExpressionWithOnce() int {
	type (
		t1 map[string]any
		t2 map[int]t1
		t3 map[complex64]t2
		t4 struct {
			a []t3
			b func()
		}
	)
	(*(t4{
		a: []t3{
			t3{
				1.5 + 2.5i: t2{
					+7*9 ^ 12: t1{
						"a" + "b": &structContainingOnce{},
					},
				},
			},
		},
		b: func() {},
	}.a[0:1:1][0:1][0][1.5+2.5i][51]["ab"].(*structContainingOnce))).b.Do(
		func() { callos.Foo() })
	return 0
}

// UninterestingOnceDo calls Do on a sync.Once.  The function passed to Do is
// not interesting.
func UninterestingOnceDo() int {
	var once sync.Once
	once.Do(func() {})
	return 54321
}

// foo is a type to use with sort.Sort.
type foo []int

func (f foo) Len() int      { return len(f) }
func (f foo) Swap(x, y int) { f[x], f[y] = f[y], f[x] }
func (f foo) Less(x, y int) bool {
	a := callos.Foo() // interesting
	return f[x] < a && a <= f[y]
}

// bar is a type to use with sort.Sort.
type bar []int

func (b bar) Len() int      { return len(b) }
func (b bar) Swap(x, y int) { b[x], b[y] = b[y], b[x] }
func (b bar) Less(x, y int) bool {
	a := callutf8.Foo() // not interesting
	return b[x] < a && a <= b[y]
}

// InterestingSort calls sort.Sort with an argument whose Less method has an
// interesting capability.
func InterestingSort() int {
	f := foo{1, 2}
	sort.Sort(f)
	return f[0]
}

// InterestingSortViaFunction calls sort.Sort via a function-valued variable,
// The analysis will not be able to analyze the behavior of the sort, but will
// report the UNANALYZED capability to inform the user of this.
func InterestingSortViaFunction() int {
	fn := sort.Sort
	s := foo{1, 2}
	fn(s)
	return s[0]
}

// UninterestingSort calls sort.Sort with an argument whose methods have no
// interesting capabilities.
func UninterestingSort() int {
	b := bar{1, 2}
	sort.Sort(b)
	return b[0]
}

// InterestingSortSlice calls sort.Slice with an argument that has an
// interesting capability.
func InterestingSortSlice() int {
	f := bar{1}
	sort.Slice(f, func(a, b int) bool { os.Getenv("foo"); return false })
	return f[0]
}

// UninterestingSortSlice calls sort.Slice with an argument that has no
// interesting capabilities.
func UninterestingSortSlice() int {
	f := bar{1}
	sort.Slice(f, func(a, b int) bool { return false })
	return f[0]
}

// InterestingSortSliceNested calls sort.Slice with an argument that itself
// calls sort.Slice.  The inner sort's function argument has an interesting
// capability.
func InterestingSortSliceNested() int {
	f := []bar{bar{1, 2}, bar{3, 4}}
	sort.Slice(f, func(a, b int) bool {
		for _, x := range [2]int{a, b} {
			sort.Slice(f[x], func(a, b int) bool { os.Getenv("foo"); return f[x][a] < f[x][b] })
		}
		return f[a][0] < f[b][0]
	})
	return f[0][0]
}

// UninterestingSortSliceNested calls sort.Slice with an argument that itself
// calls sort.Slice.  The inner sort's function argument has no interesting
// capabilities.
func UninterestingSortSliceNested() int {
	f := []bar{bar{1, 2}, bar{3, 4}}
	sort.Slice(f, func(a, b int) bool {
		for _, x := range [2]int{a, b} {
			sort.Slice(f[x], func(a, b int) bool { return f[x][a] < f[x][b] })
		}
		return f[a][0] < f[b][0]
	})
	return f[0][0]
}

// InterestingSortSliceStable calls sort.SliceStable with an argument that has an
// interesting capability.
func InterestingSortSliceStable() int {
	f := bar{1}
	sort.SliceStable(f, func(a, b int) bool { os.Getenv("foo"); return false })
	return f[0]
}

// UninterestingSortSliceStable calls sort.SliceStable with an argument that has no
// interesting capabilities.
func UninterestingSortSliceStable() int {
	f := bar{1}
	sort.SliceStable(f, func(a, b int) bool { return false })
	return f[0]
}

// InterestingSyncPool calls Get on a Pool whose New function has an
// interesting capability.
func InterestingSyncPool() int {
	p := sync.Pool{New: func() any {
		x := callos.Foo() // interesting
		return &x
	}}
	return *p.Get().(*int)
}

// UninterestingSyncPool calls Get on a Pool whose New function has no
// interesting capabilities.
func UninterestingSyncPool() int {
	p := sync.Pool{New: func() any {
		x := callutf8.Foo() // not interesting
		return &x
	}}
	return *p.Get().(*int)
}

// Asm calls an assembly function indirectly.
func Asm() int {
	return useasm.Foo() + 1
}

// AllowedAsmInStdlib calls an assembly function indirectly.  That function
// is categorized as "safe" in interesting.go.
func AllowedAsmInStdlib() int {
	return strings.Index("foo", "f") + bytes.Index([]byte{1, 2, 3}, []byte{4, 5, 6})
}

// Linkname indirectly calls a function that uses go:linkname.
func Linkname() int {
	return int(uselinkname.Foo()) + 1
}

// CallViaStdlib uses a standard library function to call an interesting
// function by passing it as an argument.
func CallViaStdlib() int {
	return strings.IndexFunc("ab", func(r rune) bool {
		return callnet.Foo() == int(r)
	})
}

// a is used as a type argument for a generic function.
type a int

// Baz has the network capability.
func (a a) Baz() int {
	_, err := net.Dial("a", "b")
	if err == nil {
		return 1
	}
	return 2
}

// CallGenericFunction calls a generic function in another package, using
// "a" as a type argument.
func CallGenericFunction() int {
	var a a
	return usegenerics.Foo(a, 1) + 1
}

// CallGenericFunctionTransitively calls a non-generic function which calls
// a generic function.
func CallGenericFunctionTransitively() int {
	return usegenerics.Bar() + 1
}

type src struct{}

func (s src) Int63() int64 {
	return int64(callnet.Foo())
}
func (s src) Seed(seed int64) {
}

// UseBigIntRand calls an interesting function via a random-number
// generator passed to (*math/big.Int).Rand.
func UseBigIntRand() int {
	var s src
	r := rand.New(s)
	x := big.NewInt(12345)
	x = x.Rand(r, x)
	return int(x.Int64())
}
