// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package usereflect is used for testing.
package usereflect

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"sync"
	"unsafe"

	"github.com/google/capslock/testpkgs/callnet"
)

// ValueSetFunc uses (reflect.Value).Set to change a func variable
// to point to a different function, then calls it.
func ValueSetFunc() int {
	f := func() int { return 42 }
	v1 := reflect.ValueOf(&f)
	v2 := v1.Elem()
	v3 := reflect.ValueOf(callnet.Foo)
	v2.Set(v3)
	return f()
}

// ValueSetInt uses (reflect.Value).Set to change an int.
func ValueSetInt() int {
	f := 123
	g := 456
	reflect.ValueOf(&f).Elem().Set(reflect.ValueOf(g))
	return f
}

type fooer interface {
	foo() int
}

type t1 int

func (_ t1) foo() int { return 42 }

type t2 int

func (_ t2) foo() int { return callnet.Foo() + 1 }

// ValueSetInterface uses (reflect.Value).Set to change an interface
// variable to a value with a different concrete type.
func ValueSetInterface() int {
	var f fooer = t1(1)
	var g fooer = t2(1)
	reflect.ValueOf(&f).Elem().Set(reflect.ValueOf(g))
	return f.foo()
}

// MakeFunc sets a func variable to an interesting function using MakeFunc and
// (reflect.Value).Set.
func MakeFunc() int {
	f1 := func() int { return 42 }
	f2 := func(_ []reflect.Value) []reflect.Value {
		x := callnet.Foo() + 1
		return []reflect.Value{reflect.ValueOf(x)}
	}
	v := reflect.MakeFunc(reflect.ValueOf(f1).Type(), f2)
	reflect.ValueOf(&f1).Elem().Set(v)
	return f1()
}

// TypeConfusionWithNewAt modifies a func pointer using reflect.NewAt and
// (reflect.Value).Set.
func TypeConfusionWithNewAt() int {
	f := func() int { return 42 }
	g := func() int { return callnet.Foo() + 1 }
	fp := &f
	v := reflect.NewAt(reflect.TypeOf(uintptr(0)), unsafe.Pointer(&fp)).Elem()
	// v now has type uintptr, but refers to fp.
	v.Set(reflect.ValueOf(uintptr(unsafe.Pointer(&g))))
	return (*fp)()
}

// TypeConfusionWithNewAtTwo modifies a func pointer using reflect.NewAt and
// (reflect.Value).Interface.
func TypeConfusionWithNewAtTwo() int {
	f := func() int { return 42 }
	g := func() int { return callnet.Foo() + 1 }
	fp := &f
	v := reflect.NewAt(reflect.TypeOf(uintptr(0)), unsafe.Pointer(&fp)).Interface()
	*v.(*uintptr) = uintptr(unsafe.Pointer(&g))
	return (*fp)()
}

// TypeConfusionWithValueRace uses concurrent writes to a reflect.Value to
// create a Value that refers to a func pointer but which has type uintptr.
func TypeConfusionWithValueRace() int {
	var (
		fn               = func() int { return 42 }
		goal             = callnet.Foo
		fnp  *func() int = &fn
		u    uintptr     = 12345
		done             = false
	)
	for !done {
		// v will contain reflect.Value variables each of which has type
		// *uintptr or **func() int, pointing to u or fnp respectively.
		// We start two goroutines which copy these values from one to another,
		// trying to create a torn reflect.Value that has type *uintptr but which
		// points to fnp.  Then we can write any uintptr to that Value using Set,
		// making *fnp point to an arbitrary function (in this case, callnet.Foo).
		var v [100]reflect.Value
		for i := 0; i < 100; i = i + 2 {
			v[i], v[i+1] = reflect.ValueOf(&u), reflect.ValueOf(&fnp)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			for i := 0; i < 1e7; i++ {
				v[i%100] = v[(i+1)%100]
			}
			wg.Done()
		}()
		go func() {
			for i := 0; i < 1e7; i++ {
				v[i%100] = v[(i+12)%100]
			}
			wg.Done()
		}()
		wg.Wait()
		for i := 0; i < 100; i++ {
			v := v[i].Elem()
			if v.Kind() != reflect.Uintptr {
				continue
			}
			if v.Uint() == 12345 {
				continue
			}
			done = true
			v.SetUint(uint64(uintptr(unsafe.Pointer(&goal))))
		}
	}
	return (*fnp)()
}

// ChangeSliceCapacityWithSliceHeader uses reflect.SliceHeader to directly
// modify the capacity of a slice, in order to overwrite a func pointer.
func ChangeSliceCapacityWithSliceHeader() int {
	var (
		fn   = func() int { return 42 }
		goal = callnet.Foo
		a    = make([]uintptr, 1)
		b    = make([]*func() int, 1)
		ah   = (*reflect.SliceHeader)(unsafe.Pointer(&a))
		bh   = (*reflect.SliceHeader)(unsafe.Pointer(&b))
	)
	for bh.Data < ah.Data {
		if rand.Intn(2) == 0 {
			a = make([]uintptr, 1)
		} else {
			b = make([]*func() int, 1)
		}
	}
	n := (bh.Data - ah.Data) / unsafe.Sizeof(a[0])
	ah.Cap = int(n + 1)
	ah.Len = int(n + 1)
	b[0] = &fn
	a[n] = uintptr(unsafe.Pointer(&goal))
	return (*b[0])()
}

// ReadValue reads a number from a value using reflect.
func ReadValue(x any) int {
	v := reflect.ValueOf(x)
	switch {
	case v.CanUint():
		return int(v.Uint())
	case v.CanInt():
		return int(v.Int())
	case v.CanFloat():
		return int(v.Float())
	}
	return 0
}

// JSONUnmarshal uses encoding/json to decode into a plain int.
func JSONUnmarshal() int {
	var x int
	json.Unmarshal([]byte("42"), &x)
	return x
}

type u int

func (x *u) UnmarshalJSON([]byte) error {
	*x = u(callnet.Foo() + 1)
	return nil
}

// JSONUnmarshalTwo uses encoding/json to decode into a type that has
// custom Unmarshal code.
func JSONUnmarshalTwo() int {
	var u u
	json.Unmarshal([]byte("42"), &u)
	return int(u)
}

var (
	f                  func() int
	g                  uintptr
	globalValue1       = reflect.ValueOf(f)
	globalValue2       = reflect.ValueOf(g)
	globalValueStruct1 = rvs{42, reflect.ValueOf(f), 42}
	globalValueStruct2 = rvs{42, reflect.ValueOf(g), 42}
	valueSlice1        = []reflect.Value{reflect.ValueOf(f)}
	valueSlice2        = []reflect.Value{reflect.ValueOf(g)}
)

// CopyValue copies a reflect.Value.
func CopyValue() {
	var f func() int
	var g uintptr
	v := reflect.ValueOf(f)
	w := reflect.ValueOf(g)
	v = w
	_ = v
}

// CopyValueGlobal copies a reflect.Value that is not a local variable.
func CopyValueGlobal() {
	globalValue1 = globalValue2
}

// CopyValueConcurrently does concurrent copies to a reflect.Value.
func CopyValueConcurrently() {
	var f func() int
	var g uintptr
	var v reflect.Value
	go func() {
		v = reflect.ValueOf(f)
	}()
	go func() {
		v = reflect.ValueOf(g)
	}()
	_ = v
}

// CopyValueViaPointer copies a reflect.Value via a pointer.
func CopyValueViaPointer() {
	var f func() int
	var g uintptr
	v := reflect.ValueOf(f)
	w := reflect.ValueOf(g)
	p := &v
	*p = w
	_ = v
}

type rv = reflect.Value

// CopyValueEquivalent copies a value with a type equivalent to reflect.Value.
func CopyValueEquivalent() {
	var f func() int
	var g uintptr
	v := rv(reflect.ValueOf(f))
	w := rv(reflect.ValueOf(g))
	v = w
	_ = v
}

// CopyValueEquivalentViaPointer copies a value with a type equivalent to reflect.Value
// via a pointer.
func CopyValueEquivalentViaPointer() {
	var f func() int
	var g uintptr
	v := rv(reflect.ValueOf(f))
	w := rv(reflect.ValueOf(g))
	p := &v
	*p = w
	_ = v
}

// rvs is a struct that contains a field of type reflect.Value.
type rvs struct {
	x int
	v reflect.Value
	y float32
}

// CopyValueContainingStruct copies a struct containing a reflect.Value.
func CopyValueContainingStruct() {
	var f func() int
	var g uintptr
	v := rvs{42, reflect.ValueOf(f), 42}
	w := rvs{42, reflect.ValueOf(g), 42}
	v = w
	_ = v
}

// CopyValueContainingStructViaPointer copies a struct containing a reflect.Value via a pointer.
func CopyValueContainingStructViaPointer() {
	var f func() int
	var g uintptr
	v := rvs{42, reflect.ValueOf(f), 42}
	w := rvs{42, reflect.ValueOf(g), 42}
	p := &v
	*p = w
	_ = v
}

// CopyValueInArray copies a reflect.Value in an array.
func CopyValueInArray() {
	var f func() int
	var g uintptr
	v := [1]reflect.Value{reflect.ValueOf(f)}
	w := [1]reflect.Value{reflect.ValueOf(g)}
	v = w
	_ = v
}

// CopyValueInArrayViaPointer copies a reflect.Value in an array via a pointer.
func CopyValueInArrayViaPointer() {
	var f func() int
	var g uintptr
	v := [1]reflect.Value{reflect.ValueOf(f)}
	w := [1]reflect.Value{reflect.ValueOf(g)}
	p := &v
	*p = w
	_ = v
}

// CopyValueInMultipleAssignment copies a reflect.Value using an assignment of
// multiple values.
func CopyValueInMultipleAssignment() {
	var f func() int
	var g uintptr
	v := reflect.ValueOf(f)
	w := reflect.ValueOf(g)
	var a, b, c, d int
	a, v, b = c, w, d
	_, _, _, _, _ = v, a, b, c, d
}

// CopyValueInMultipleAssignmentViaPointer copies a reflect.Value via a pointer
// using an assignment of multiple values.
func CopyValueInMultipleAssignmentViaPointer() {
	var f func() int
	var g uintptr
	v := reflect.ValueOf(f)
	w := reflect.ValueOf(g)
	var a, b, c, d int
	p := &v
	a, *p, b = c, w, d
	_, _, _, _, _ = v, a, b, c, d
}

// CopyValueInCommaOk copies a reflect.Value using a "comma-ok" assignment.
func CopyValueInCommaOk() {
	var f func() int
	var g uintptr
	v := reflect.ValueOf(f)
	w := map[int]reflect.Value{1: reflect.ValueOf(g)}
	var ok bool
	v, ok = w[1]
	_, _ = v, ok
}

// CopyValueInStructField copies a reflect.Value field in a struct.
func CopyValueInStructField() {
	var f func() int
	var g uintptr
	v := rvs{42, reflect.ValueOf(f), 42}
	w := rvs{42, reflect.ValueOf(g), 42}
	v.v = w.v
	_ = v
}

// CopyValueInStructFieldViaPointer copies a reflect.Value field in a struct
// via a pointer.
func CopyValueInStructFieldViaPointer() {
	var f func() int
	var g uintptr
	v := &rvs{42, reflect.ValueOf(f), 42}
	w := rvs{42, reflect.ValueOf(g), 42}
	v.v = w.v
	_ = v
}

// RangeValue copies to a reflect.Value using a range clause.
func RangeValue() {
	var x reflect.Value
	for _, x = range valueSlice1 {
	}
	for _, x = range valueSlice2 {
	}
	_ = x
}

// RangeValueTwo does concurrent copies to a reflect.Value using range clauses.
func RangeValueTwo() {
	var x reflect.Value
	go func() {
		for _, x = range valueSlice1 {
		}
	}()
	go func() {
		for _, x = range valueSlice2 {
		}
	}()
	_ = x
}
