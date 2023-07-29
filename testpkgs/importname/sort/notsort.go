// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package sort is not really the sort package.
package sort

import "os"

// Sort calls os.ReadFile.
func Sort(f any) {
	os.ReadFile("/tmp/zzzzzz")
}
