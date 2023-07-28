// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package callos is used for testing.
package callos

import (
	"os"
	"os/exec"
	"os/user"
)

// Foo is a test function.
func Foo() int {
	return 42 + os.Getpid()
}

// Bar is a test function which calls os/exec.Command and
// (*os/exec.Cmd).Run.
func Bar() int {
	err := exec.Command("a", "b").Run()
	if err != nil {
		return 1
	}
	return 0
}

// Baz is a test function which calls os/user.Current.
func Baz() int {
	u, _ := user.Current()
	return len(u.Username)
}
