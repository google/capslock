// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Program capslock loads packages specified in command line arguments,
// and for each function in those packages that has interesting capabilities,
// outputs a string describing this to stdout.
//
// The exit status code is 2 for an error, 1 if a difference is found when a
// comparison is requested, and 0 otherwise.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
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
	cpuprofile     = flag.String("cpuprofile", "", "write cpu profile to specified file")
	memprofile     = flag.String("memprofile", "", "write memory profile to specified file")
	granularity    = flag.String("granularity", "package",
		`the granularity to use for comparisons, either "package" or "function".`)
)

func main() {
	flag.Parse()
	// The main logic is in 'run' so that deferred functions run before we reach os.Exit.
	err := run()
	switch err.(type) {
	case nil:
	case analyzer.DifferenceFoundError:
		os.Exit(1)
	default:
		log.Print(err)
		os.Exit(2)
	}
}

func run() error {
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile file: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	packageNames := strings.Split(*packageList, ",")
	if *disableBuiltin && *customMap == "" {
		return fmt.Errorf("Error: --disable_builtin only makes sense with a --capability_map file specified")
	}
	var classifier *interesting.Classifier
	if *customMap != "" {
		f, err := os.Open(*customMap)
		if err != nil {
			return err
		}
		classifier, err = interesting.LoadClassifier(*customMap, f, *disableBuiltin)
		if err != nil {
			return err
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
		return fmt.Errorf("Error loading packages: %w", err)
	}
	if len(pkgs) == 0 {
		return fmt.Errorf("No packages matching %v", packageNames)
	}

	queriedPackages := analyzer.GetQueriedPackages(pkgs)
	if *verbose > 0 {
		for _, p := range pkgs {
			log.Printf("Loaded package %q\n", p.Name)
		}
	}
	if packages.PrintErrors(pkgs) > 0 {
		return fmt.Errorf("Some packages had errors. Aborting analysis.")
	}
	err = analyzer.RunCapslock(flag.Args(), *output, pkgs, queriedPackages, &analyzer.Config{
		Classifier:     classifier,
		DisableBuiltin: *disableBuiltin,
		Granularity:    *granularity,
	})

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			return fmt.Errorf("could not create memory profile file: %w", err)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("could not write memory profile: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("could not close memory profile file: %w", err)
		}
	}
	return err
}
