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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"

	"github.com/google/capslock/analyzer"
	"github.com/google/capslock/interesting"
	"golang.org/x/tools/go/packages"
)

var (
	packageList    = flag.String("packages", "", "target patterns to be analysed; allows wildcarding")
	output         = flag.String("output", "", "output mode to use; non-default options are json, m, package, v, graph, and compare")
	verbose        = flag.Int("v", 0, "verbosity level")
	noiseFlag      = flag.Bool("noisy", false, "include output on unanalyzed function calls (can be noisy)")
	customMap      = flag.String("capability_map", "", "use a custom capability map file")
	disableBuiltin = flag.Bool("disable_builtin", false, "when using a custom capability map, disable the builtin capability mappings")
	capabilities   = flag.String("capabilities", "", "if non-empty, a comma-separated list of capabilities to consider for graph output.  Optionally, all capabilities can be prefixed with '-' to specify capabilities to ignore.")
	buildTags      = flag.String("buildtags", "", "command-separated list of build tags to use when loading packages")
	goos           = flag.String("goos", "", "GOOS value to use when loading packages")
	goarch         = flag.String("goarch", "", "GOARCH value to use when loading packages")
	cpuprofile     = flag.String("cpuprofile", "", "write cpu profile to specified file")
	memprofile     = flag.String("memprofile", "", "write memory profile to specified file")
	granularity    = flag.String("granularity", "",
		`the granularity to use for comparisons, either "package" or "function".`)
	forceLocalModule = flag.Bool("force_local_module", false, "if the requested packages cannot be loaded in the current workspace, return an error immediately, instead of trying to load them in a temporary module")
	omitPaths        = flag.Bool("omit_paths", false, "omit example call paths from output")
	version          = flag.Bool("version", false, "report Capslock version and exit")
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
	if *version {
		// Output version information and exit.
		//
		// debug.ReadBuildInfo returns build information embedded in the binary.
		if info, ok := debug.ReadBuildInfo(); ok {
			escape := func(s string) string {
				// escape any control characters if they somehow made it here, but
				// leave out the surrounding quotation marks.
				return strings.TrimPrefix(strings.TrimSuffix(strconv.Quote(s), `"`), `"`)
			}
			if _, err := fmt.Printf("capslock version %s\n", escape(info.Main.Version)); err != nil {
				return err
			}
			if _, err := fmt.Printf("compiled with Go version %s\n", escape(info.GoVersion)); err != nil {
				return err
			}
			for _, d := range info.Deps {
				if d.Path == "golang.org/x/tools" {
					for d.Replace != nil {
						d = d.Replace
					}
					if _, err := fmt.Printf("includes Go tools version %s\n", escape(d.Version)); err != nil {
						return err
					}
					break
				}
			}
		} else {
			if _, err := fmt.Printf("capslock version unknown\n"); err != nil {
				return err
			}
		}
		return nil
	}

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
	g, err := analyzer.GranularityFromString(*granularity)
	if err != nil {
		return fmt.Errorf("parsing flag -granularity: %w", err)
	}
	cs, err := analyzer.NewCapabilitySet(*capabilities)
	if err != nil {
		return fmt.Errorf("parsing flag -capabilities: %w", err)
	}
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

	loadConfig := analyzer.LoadConfig{
		BuildTags: *buildTags,
		GOOS:      *goos,
		GOARCH:    *goarch,
	}
	pkgs, listFailed, failedPackage, err := loadPackages(packageNames, loadConfig)
	if (listFailed || len(pkgs) == 0) && !*forceLocalModule {
		// Either:
		// - `go list` returned an error for one of the packages, perhaps because
		//   it is not a dependency of the current workspace; or
		// - no packages were loaded, because paths with '...' wildcards matched
		//   no dependencies of the current workspace.
		//
		// Here we try again in a temporary module, in which we call `go get` for
		// each package.
		//
		// -force_local_module disables this behavior, and returns an error
		// instead.
		if listFailed {
			fmt.Fprintf(os.Stderr, "Couldn't load package %q in the current module.", failedPackage)
		} else {
			fmt.Fprintf(os.Stderr, "Found no packages matching %q in the current module.", packageNames)
		}
		fmt.Fprintf(os.Stderr, "  Trying again in a temporary module.\n")

		// Save current working directory.
		var wd string
		wd, err = os.Getwd()
		if err != nil {
			return err
		}

		// Create a temporary module, switch to it, and `go get` the requested packages.
		var remove func()
		remove, err = makeTemporaryModule(packageNames)
		if remove != nil {
			defer remove()
		}
		if err != nil {
			return err
		}

		// Try loading the packages again.
		pkgs, _, _, err = loadPackages(packageNames, loadConfig)

		// Switch back to the original working directory.
		err1 := os.Chdir(wd)
		if err == nil && err1 != nil {
			return fmt.Errorf("returning to working directory: %w", err1)
		}
	}
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
	if printErrors(pkgs) {
		return fmt.Errorf("Some packages had errors. Aborting analysis.")
	}
	err = analyzer.RunCapslock(flag.Args(), *output, pkgs, queriedPackages, &analyzer.Config{
		Classifier:     classifier,
		DisableBuiltin: *disableBuiltin,
		Granularity:    g,
		CapabilitySet:  cs,
		OmitPaths:      *omitPaths,
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

// loadPackages calls analyzer.LoadPackages to load the specified packages.
//
// If it fails due to a ListError (for example, if one of the packages is not a
// dependency of the current module), the return value listFailed will be true,
// and failedPackage will specify the package that couldn't be loaded.
func loadPackages(packageNames []string, loadConfig analyzer.LoadConfig) (pkgs []*packages.Package, listFailed bool, failedPackage string, err error) {
	pkgs, err = analyzer.LoadPackages(packageNames, loadConfig)
	for _, p := range pkgs {
		for _, e := range p.Errors {
			if e.Kind == packages.ListError {
				return pkgs, true, p.ID, err
			}
		}
	}
	return pkgs, false, "", err
}

// makeTemporaryModule switches to a new temporary directory, creates a module
// there, and adds the specified packages to that module with `go get`.
//
// It also sets the environment variable GOWORK to "off", to avoid analyses
// being affected by workspaces we did not intend to use.  (For example, if
// there's a go.work file in /tmp.)
//
// The caller can call the returned function, if it is non-nil, to remove the
// temporary directory containing the module when it is no longer needed.
func makeTemporaryModule(packageNames []string) (remove func(), err error) {
	if err = os.Setenv("GOWORK", "off"); err != nil {
		return nil, err
	}
	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("creating temporary directory: %w", err)
	}
	remove = func() { os.RemoveAll(tmpdir) }
	if err = os.Chdir(tmpdir); err != nil {
		return remove, fmt.Errorf("switching to temporary directory: %w", err)
	}
	run := func(command string, args ...string) error {
		if *verbose >= 2 {
			log.Printf("running %q with args %q", command, args)
		}
		cmd := exec.Command(command, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil || *verbose >= 2 {
			os.Stderr.Write(stderr.Bytes())
		}
		return err
	}
	if err = run("go", "mod", "init", "capslockmodule"); err != nil {
		return remove, fmt.Errorf("creating temporary module: %w", err)
	}
	for _, p := range packageNames {
		if err := run("go", "get", p); err != nil {
			return remove, fmt.Errorf("calling `go get %q`: %w", p, err)
		}
	}
	return remove, nil
}

func printErrors(pkgs []*packages.Package) (anyErrors bool) {
	var (
		buf           bytes.Buffer
		stop          = false
		skippedErrors = 0
	)
	const limit = 1000

	add := func(err error) {
		anyErrors = true
		if stop {
			skippedErrors++
			return
		}
		fmt.Fprintln(&buf, err)
		if buf.Len() > limit {
			stop = true
			buf.Truncate(limit)
			buf.WriteString("(...truncated)\n")
		}
	}

	// Print module errors.
	seen := make(map[*packages.Module]bool)
	packages.Visit(pkgs, func(p *packages.Package) bool {
		if mod := p.Module; mod != nil && seen[mod] == false {
			seen[mod] = true
			if err := mod.Error; err != nil {
				add(errors.New(err.Err))
			}
		}
		return true
	}, nil)

	// Print package errors.
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, err := range p.Errors {
			add(err)
		}
	})

	if anyErrors {
		os.Stderr.Write(buf.Bytes())
		switch {
		case skippedErrors == 1:
			os.Stderr.WriteString("(1 more error)\n")
		case skippedErrors > 1:
			fmt.Fprintf(os.Stderr, "(%d more errors)\n", skippedErrors)
		}
	}
	return anyErrors
}
