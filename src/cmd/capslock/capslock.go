// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Program capslock loads packages specified in command line arguments,
// and for each function in those packages that has interesting capabilities,
// outputs a string describing this to stdout.
package main

import (
	"flag"
	"log"
	"strings"

	"capslock/analyzer"
)

var (
	packageList = flag.String("packages", "", "target patterns to be analysed; allows wildcarding")
	output      = flag.String("output", "", "output mode to use; non-default options are json, m, v, graph, and compare")
	noiseFlag   = flag.Bool("noisy", false, "include output on unanalyzed function calls (can be noisy)")
	buildTags   = flag.String("buildtags", "", "command-separated list of build tags to use when loading packages")
	goos        = flag.String("goos", "", "GOOS value to use when loading packages")
	goarch      = flag.String("goarch", "", "GOARCH value to use when loading packages")
)

func main() {
	flag.Parse()
	packageNames := strings.Split(*packageList, ",")
	if len(packageNames) == 0 {
		log.Fatal("No packages provided")
	}

	classifier := analyzer.GetClassifier(*noiseFlag)

	pkgs := analyzer.LoadPackages(packageNames,
		analyzer.LoadConfig{
			BuildTags: *buildTags,
			GOOS:      *goos,
			GOARCH:    *goarch,
		})
	if len(pkgs) == 0 {
		log.Fatalf("No packages matching %v", packageNames)
	}

	queriedPackages := analyzer.GetQueriedPackages(pkgs)
	for _, p := range pkgs {
		log.Printf("Loaded package %q\n", p.Name)
	}
	err := analyzer.RunCapslock(flag.Args(), *output, pkgs, queriedPackages, classifier)
	if err != nil {
		log.Fatal(err)
	}
}
