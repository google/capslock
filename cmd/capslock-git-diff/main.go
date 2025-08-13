// Copyright 2024 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// capslock-git-diff lists package capabilities that were added between
// two revisions of a git repository.
//
// Usage example:
//
//	capslock-git-diff main mybranch somepath/...
//
// This requires Capslock to be installed:
//
//	go install github.com/google/capslock/cmd/capslock@latest
//
// To compare against the current state of the repository, specify "." as a
// revision:
//
//	capslock-git-diff main . somepath/...
//
// If only two arguments are supplied, all packages under the current directory
// are used.
//
// If the environment variable CAPSLOCKTOOLSTMPDIR is set and non-empty, it
// specifies the directory where temporary files are created.  Otherwise the
// system temporary directory is used.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	cpb "github.com/google/capslock/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	verbose          = flag.Bool("v", false, "enable verbose logging")
	granularity      = flag.String("granularity", "intermediate", "the granularity to use for comparisons")
	flagCapabilities = flag.String("capabilities", "-UNANALYZED", "if non-empty, a comma-separated list of capabilities to pass to capslock")
)

func vlog(format string, a ...any) {
	if !*verbose {
		return
	}
	log.Printf(format, a...)
}

// run executes the specified command and writes its stdout to w.
func run(w io.Writer, command string, args ...string) error {
	vlog("running %s with args %q", command, args)
	cmd := exec.Command(command, args...)
	cmd.Stdout = w
	var stderr bytes.Buffer
	if *verbose {
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Run(); err != nil {
		if !*verbose {
			// We didn't output the command line, or the command's stderr earlier.
			// Since it failed, we output them now.
			log.Printf("running %s with args %q:", command, args)
			os.Stderr.Write(stderr.Bytes())
		}
		return fmt.Errorf("%s: %w", command, err)
	}
	return nil
}

func AnalyzeAtRevision(rev, pkgname string) (cil *cpb.CapabilityInfoList, err error) {
	vlog("analyzing at revision %q", rev)
	if rev == "." {
		return callCapslock(rev, pkgname)
	}
	// Make a temporary directory.
	tmpdir, err := os.MkdirTemp(os.Getenv("CAPSLOCKTOOLSTMPDIR"), "")
	if err != nil {
		return nil, fmt.Errorf("creating temporary directory: %w", err)
	}
	defer func() {
		if err1 := os.RemoveAll(tmpdir); err1 != nil {
			log.Printf("Error removing temporary directory %q: %v", tmpdir, err1)
		}
	}()
	// Get the location of the .git directory, so we can make a temporary clone.
	var b bytes.Buffer
	if err = run(&b, "git", "rev-parse", "--git-dir"); err != nil {
		return nil, err
	}
	gitdir := strings.TrimSuffix(b.String(), "\n")
	vlog("git directory: %q", gitdir)
	b.Reset()
	// Get the relative directory within the git repository.
	if err = run(&b, "git", "rev-parse", "--show-prefix"); err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(b.String(), "\n")
	vlog("current path in repository: %q", prefix)
	b.Reset()
	// Clone the repo.
	if err = run(nil, "git", "clone", "--shared", "--no-checkout", "--", gitdir, tmpdir); err != nil {
		return nil, err
	}
	// Temporarily switch directory.
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	defer func() {
		// Switch back to the original directory.
		err1 := os.Chdir(wd)
		if err == nil && err1 != nil {
			err = fmt.Errorf("returning to working directory: %w", err1)
		}
		vlog("returned to working directory %q", wd)
	}()
	if err = os.Chdir(tmpdir); err != nil {
		return nil, fmt.Errorf("switching to temporary directory: %w", err)
	}
	vlog("switched to directory %q", tmpdir)
	// Checkout the revision.
	if err = run(nil, "git", "checkout", rev, "--"); err != nil {
		return nil, err
	}
	// Go to the same directory in the clone.
	path := filepath.Join(tmpdir, prefix)
	if err = os.Chdir(path); err != nil {
		return nil, fmt.Errorf("switching to temporary directory: %w", err)
	}
	vlog("switched to directory %q", path)
	return callCapslock(rev, pkgname)
}

func callCapslock(rev, pkgname string) (cil *cpb.CapabilityInfoList, err error) {
	// Call capslock.
	var b bytes.Buffer
	args := []string{
		"-packages=" + pkgname,
		"-output=json",
		"-granularity=" + *granularity,
	}
	if *flagCapabilities != "" {
		args = append(args, "-capabilities="+*flagCapabilities)
	}
	if err = run(&b, "capslock", args...); err != nil {
		return nil, err
	}
	if *verbose {
		str := string(b.Bytes())
		if len(str) > 103 {
			str = str[:100] + "..."
		}
		vlog("capslock returned %q", str)
	}
	// Unmarshal the output.
	cil = new(cpb.CapabilityInfoList)
	if err = protojson.Unmarshal(b.Bytes(), cil); err != nil {
		return nil, fmt.Errorf("Couldn't parse analyzer output: %w", err)
	}
	vlog("parsed CapabilityInfoList with %d entries", len(cil.CapabilityInfo))
	return cil, nil
}

func usage() {
	fmt.Fprintf(os.Stderr,
		`capslock-git-diff lists package capabilities that were added between
two revisions of a git repository.

Usage: capslock-git-diff <revision1> <revision2> [<package>]
`)
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	a := flag.Args()
	var pkgname string
	if len(a) == 2 {
		// By default, use the current directory and its subdirectories.
		pkgname = "./..."
	} else if len(a) == 3 {
		pkgname = a[2]
	} else {
		fmt.Fprintf(os.Stderr, "wrong number of arguments: %q\n\n", a)
		usage()
	}
	revisions := [2]string{a[0], a[1]}
	cil1, err := AnalyzeAtRevision(revisions[0], pkgname)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	cil2, err := AnalyzeAtRevision(revisions[1], pkgname)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	different := diffCapabilityInfoLists(cil1, cil2, revisions, pkgname)
	if different {
		os.Exit(1)
	}
}

type mapKey struct {
	key        string
	capability cpb.Capability
}
type capabilitiesMap map[mapKey]*cpb.CapabilityInfo

func populateMap(cil *cpb.CapabilityInfoList, granularity string) capabilitiesMap {
	m := make(capabilitiesMap)
	for _, ci := range cil.GetCapabilityInfo() {
		var key string
		switch granularity {
		case "package", "intermediate":
			key = ci.GetPackageDir()
		case "function", "":
			if len(ci.Path) == 0 {
				continue
			}
			key = ci.Path[0].GetName()
		default:
			panic("unknown granularity " + granularity)
		}
		if key == "" {
			continue
		}
		m[mapKey{capability: ci.GetCapability(), key: key}] = ci
	}
	return m
}

func cover(pending map[string]bool, ci *cpb.CapabilityInfo) (covered []string) {
	for _, p := range ci.Path {
		var key string
		switch *granularity {
		case "package", "intermediate":
			key = p.GetPackage()
		case "function", "":
			key = p.GetName()
		}
		if key == "" {
			continue
		}
		if pending[key] {
			covered = append(covered, key)
			pending[key] = false
		}
	}
	sort.Strings(covered)
	return covered
}

func sortAndPrintCapabilities(cs []cpb.Capability) {
	slices.Sort(cs)
	tw := tabwriter.NewWriter(
		os.Stdout, // output
		10,        // minwidth
		8,         // tabwidth
		4,         // padding
		' ',       // padchar
		0)         // flags
	capabilityDescription := map[cpb.Capability]string{
		2:  "Access to the file system",
		3:  "Access to the network",
		4:  "Read or modify settings in the Go runtime",
		5:  "Read system information, e.g. environment variables",
		6:  "Modify system information, e.g. environment variables",
		7:  `Call miscellaneous functions in the "os" package `,
		8:  "Make system calls",
		9:  "Invoke arbitrary code, e.g. assembly or go:linkname",
		10: "Call cgo functions",
		11: "Code that Capslock cannot effectively analyze",
		12: "Uses unsafe.Pointer",
		13: "Uses reflect",
		14: "Execute other programs, usually via os/exec",
	}
	for _, c := range cs {
		fmt.Fprint(tw, "\t", cpb.Capability_name[int32(c)], ":\t", capabilityDescription[c], "\n")
	}
	tw.Flush()
}

func summarizeNewCapabilities(keys []mapKey, baselineMap, currentMap capabilitiesMap) (newlyUsedCapabilities, existingCapabilitiesWithNewUses []cpb.Capability) {
	hasAnyOldUse := make(map[cpb.Capability]bool)
	newUses := make(map[cpb.Capability]int)
	for _, key := range keys {
		_, inBaseline := baselineMap[key]
		_, inCurrent := currentMap[key]
		if inBaseline {
			hasAnyOldUse[key.capability] = true
		}
		if !inBaseline && inCurrent {
			newUses[key.capability]++
		}
	}
	newUsesOfExistingCapabilities := 0
	for c, n := range newUses {
		if !hasAnyOldUse[c] {
			newlyUsedCapabilities = append(newlyUsedCapabilities, c)
		} else {
			existingCapabilitiesWithNewUses = append(existingCapabilitiesWithNewUses, c)
			newUsesOfExistingCapabilities += n
		}
	}
	if n := len(newlyUsedCapabilities); n > 0 {
		if n == 1 {
			fmt.Println("\nAdded 1 new capability:")
		} else {
			fmt.Printf("\nAdded %d new capabilities:\n", n)
		}
		sortAndPrintCapabilities(newlyUsedCapabilities)
	}
	if n := newUsesOfExistingCapabilities; n > 0 {
		if n == 1 {
			fmt.Println("\nAdded 1 new use of existing capability:")
		} else {
			fmt.Printf("\nAdded %d new uses of existing capabilities:\n", n)
		}
		sortAndPrintCapabilities(existingCapabilitiesWithNewUses)
	}
	if len(newlyUsedCapabilities) == 0 && newUsesOfExistingCapabilities == 0 {
		switch *granularity {
		case "package":
			fmt.Printf("\nBetween those commits, none of those packages gained a new capability.\n")
		case "intermediate":
			fmt.Printf("\nBetween those commits, there were no uses of capabilities via a new package.\n")
		case "function", "":
			fmt.Printf("\nBetween those commits, no functions in those packages gained a new capability.\n")
		}
	}
	return newlyUsedCapabilities, existingCapabilitiesWithNewUses
}

func diffCapabilityInfoLists(baseline, current *cpb.CapabilityInfoList, revisions [2]string, pkgname string) (different bool) {
	fmt.Printf("Comparing capabilities in %q between revisions %q and %q\n\n",
		pkgname, revisions[0], revisions[1])
	if revisions[0] != "." && revisions[1] != "." {
		fmt.Println("Commits between the two revisions:")
		listCommits(revisions)
	}
	granularityDescription := map[string]string{
		"package":      "Package",
		"intermediate": "Package",
		"function":     "Function",
		"":             "Function",
	}[*granularity]
	baselineMap := populateMap(baseline, *granularity)
	currentMap := populateMap(current, *granularity)
	var keys []mapKey
	for k := range baselineMap {
		keys = append(keys, k)
	}
	for k := range currentMap {
		if _, ok := baselineMap[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if a, b := keys[i].capability, keys[j].capability; a != b {
			return a < b
		}
		return keys[i].key < keys[j].key
	})
	newlyUsedCapabilities, existingCapabilitiesWithNewUses :=
		summarizeNewCapabilities(keys, baselineMap, currentMap)
	// Output changes for each capability, in the order they were printed above.
	for _, list := range [][]cpb.Capability{newlyUsedCapabilities, existingCapabilitiesWithNewUses} {
		for _, c := range list {
			switch *granularity {
			case "package":
				fmt.Printf("\nNew packages with capability %s:\n", c)
			case "intermediate":
				fmt.Printf("\nNew packages in call paths to capability %s:\n", c)
			case "function":
				fmt.Printf("\nNew functions with capability %s:\n", c)
			}

			pending := make(map[string]bool)
			for _, key := range keys {
				if key.capability != c {
					continue
				}
				_, inBaseline := baselineMap[key]
				_, inCurrent := currentMap[key]
				if !inBaseline && inCurrent {
					pending[key.key] = true
					different = true
				}
			}
			for _, key := range keys {
				if key.capability != c {
					continue
				}
				if !pending[key.key] {
					// already done
					continue
				}
				ci := currentMap[key]
				if keys := cover(pending, ci); len(keys) > 1 {
					// This call path can be the example for multiple keys.
					fmt.Printf("\n%ss %s have capability %s:\n", granularityDescription, strings.Join(keys, ", "), key.capability)
				} else {
					fmt.Printf("\n%s %s has capability %s:\n", granularityDescription, key.key, key.capability)
				}
				printCallPath(ci.Path)
			}
		}
	}
	return different
}

func printCallPath(fns []*cpb.Function) {
	tw := tabwriter.NewWriter(
		os.Stdout, // output
		10,        // minwidth
		8,         // tabwidth
		2,         // padding
		' ',       // padchar
		0)         // flags
	for _, f := range fns {
		if f.Site != nil {
			fmt.Fprint(tw, f.Site.GetFilename(), ":", f.Site.GetLine(), ":", f.Site.GetColumn())
		}
		fmt.Fprint(tw, "\t", f.GetName(), "\n")
	}
	tw.Flush()
}

func listCommits(revisions [2]string) {
	var b bytes.Buffer
	run(&b, "git", "log", "--no-decorate", "--oneline", "^"+revisions[0], revisions[1])
	lines := strings.Split(b.String(), "\n")
	if len(lines) <= 120 {
		os.Stdout.Write(b.Bytes())
		return
	}
	for i := 0; i < 50; i++ {
		fmt.Println(lines[i])
	}
	fmt.Printf("(...%d commits omitted...)\n", len(lines)-100)
	for i := -50; i < 0; i++ {
		fmt.Println(lines[len(lines)+i])
	}
}
