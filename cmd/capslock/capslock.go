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
	"os"
	"strings"

	"github.com/google/capslock/analyzer"
	"github.com/google/capslock/interesting"
	"golang.org/x/tools/go/packages"
)

var (
	packageList    = flag.String("packages", "", "target patterns to be analysed; allows wildcarding")
	output         = flag.String("output", "", "output mode to use; non-default options are json, m, v, graph, and compare")
	verbose        = flag.Int("v", 0, "verbosity level")
	noiseFlag      = flag.Bool("noisy", false, "include output on unanalyzed function calls (can be noisy)")
	customMap      = flag.String("capability_map", "", "use a custom capability map file")
	disableBuiltin = flag.Bool("disable_builtin", false, "when using a custom capability map, disable the builtin capability mappings")
	buildTags      = flag.String("buildtags", "", "command-separated list of build tags to use when loading packages")
	goos           = flag.String("goos", "", "GOOS value to use when loading packages")
	goarch         = flag.String("goarch", "", "GOARCH value to use when loading packages")
)

func main() {
	flag.Parse()
	packageNames := strings.Split(*packageList, ",")
	if *disableBuiltin && *customMap == "" {
		log.Fatal("Error: --disable_builtin only makes sense with a --capability_map file specified")
	}
	var classifier *interesting.Classifier
	if *customMap != "" {
		f, err := os.Open(*customMap)
		if err != nil {
			log.Fatal(err)
		}
		classifier, err = interesting.LoadClassifier(*customMap, f, *disableBuiltin)
		if err != nil {
			log.Fatal(err)
		}
		if *noiseFlag {
			classifier = interesting.ClassifierExcludingUnanalyzed(classifier)
		}
		log.Printf("Using custom capability map %q", *customMap)
	} else {
		classifier = analyzer.GetClassifier(*noiseFlag)
	}

	pkgs, err := analyzer.LoadPackages(packageNames,
		analyzer.LoadConfig{
			BuildTags: *buildTags,
			GOOS:      *goos,
			GOARCH:    *goarch,
		})
	if err != nil {
		log.Fatalf("Error loading packages: %v", err)
	}
	if len(pkgs) == 0 {
		log.Fatalf("No packages matching %v", packageNames)
	}

	queriedPackages := analyzer.GetQueriedPackages(pkgs)
	if *verbose > 0 {
		for _, p := range pkgs {
			log.Printf("Loaded package %q\n", p.Name)
		}
	}
	if packages.PrintErrors(pkgs) > 0 {
		log.Fatal("Some packages had errors. Aborting analysis.")
	}
	err = analyzer.RunCapslock(flag.Args(), *output, pkgs, queriedPackages, &analyzer.Config{
		Classifier:     classifier,
		DisableBuiltin: *disableBuiltin,
	})
	if err != nil {
		log.Fatal(err)
	}
}
