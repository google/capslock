// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package interesting contains tools for our static analysis to determine
// whether a leaf function is interesting.
package interesting

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"sort"
	"strings"

	cpb "github.com/google/capslock/proto"
)

//go:embed interesting.cm
var interestingData string

// Type Classifier contains informatation used to map code features to
// concrete capabilities.
type Classifier struct {
	functionCategory   map[string]cpb.Capability
	unanalyzedCategory map[string]cpb.Capability
	packageCategory    map[string]cpb.Capability
	ignoredEdges       map[[2]string]struct{}
	cgoSuffixes        []string
}

var internalMap = parseInternalMapOrDie()

func newClassifier() *Classifier {
	return &Classifier{
		functionCategory:   map[string]cpb.Capability{},
		unanalyzedCategory: map[string]cpb.Capability{},
		packageCategory:    map[string]cpb.Capability{},
		ignoredEdges:       map[[2]string]struct{}{},
	}
}

func parseCapabilityMap(source string, r io.Reader) (*Classifier, error) {
	ret := newClassifier()
	scanner := bufio.NewScanner(r)
	line := 0
	for scanner.Scan() {
		line++
		// Ignore comments and empty lines.
		t := strings.Split(scanner.Text(), "#")
		if len(t) == 0 {
			continue
		}
		args := strings.Fields(t[0])
		if len(args) == 0 {
			continue
		}
		if len(args) < 2 {
			return nil, fmt.Errorf("%v:%v: invalid format", source, line)
		}
		// Keyword is first argument.
		switch args[0] {
		case "cgo_suffix":
			// Format: cgo_suffix suffix.
			ret.cgoSuffixes = append(ret.cgoSuffixes, args[1])
		case "func":
			// Format: func package/function capability
			if len(args) < 3 {
				return nil, fmt.Errorf("%v:%v: invalid %v format", source, line, args[0])
			}
			if _, ok := ret.functionCategory[args[1]]; ok {
				return nil, fmt.Errorf("%v:%v: duplicate %v key", source, line, args[0])
			}
			c, ok := cpb.Capability_value[args[2]]
			if !ok {
				return nil, fmt.Errorf("%v:%v: unsupported capability %q", source, line, args[2])
			}
			ret.functionCategory[args[1]] = cpb.Capability(c)
		case "ignore_edge":
			// Format: ignore_edge function function
			if len(args) < 3 {
				return nil, fmt.Errorf("%v:%v: invalid %v format", source, line, args[0])
			}
			k := [2]string{args[1], args[2]}
			if _, ok := ret.ignoredEdges[k]; ok {
				return nil, fmt.Errorf("%v:%v: duplicate %v key", source, line, args[0])
			}
			ret.ignoredEdges[k] = struct{}{}
		case "package":
			// Format: package package_name capability
			if len(args) < 3 {
				return nil, fmt.Errorf("%v:%v: invalid %v format", source, line, args[0])
			}
			if _, ok := ret.packageCategory[args[1]]; ok {
				return nil, fmt.Errorf("%v:%v: duplicate %v key", source, line, args[0])
			}
			c, ok := cpb.Capability_value[args[2]]
			if !ok {
				return nil, fmt.Errorf("%v:%v: unsupported capability %q", source, line, args[2])
			}
			ret.packageCategory[args[1]] = cpb.Capability(c)
		case "unanalyzed":
			// Format: unanalyzed function
			if _, ok := ret.unanalyzedCategory[args[1]]; ok {
				return nil, fmt.Errorf("%v:%v: duplicate %v key", source, line, args[0])
			}
			ret.unanalyzedCategory[args[1]] = cpb.Capability_CAPABILITY_UNANALYZED
		default:
			return nil, fmt.Errorf("%v:%v: unsupported keyword %q", source, line, args[0])
		}
	}
	return ret, nil
}

// parseInternalMapOrDie parses the internal embedded capability map data
// or panic()s if this fails.  It returns the embedded classifier.
func parseInternalMapOrDie() *Classifier {
	classifier, err := parseCapabilityMap("internal", strings.NewReader(interestingData))
	if err != nil {
		panic("internal error: " + err.Error())
	}
	if len(classifier.functionCategory) == 0 {
		panic("internal error: no capabilities loaded")
	}
	return classifier
}

// DefaultClassifier returns the default internal Classifier.
func DefaultClassifier() *Classifier {
	return internalMap
}

// ClassifierExcludingUnanalyzed returns a copy of the supplied Classifier
// that is modified to never classify capabilities as CAPABILITY_UNANALYZED.
func ClassifierExcludingUnanalyzed(classifier *Classifier) *Classifier {
	withoutUnanalyzed := *classifier
	withoutUnanalyzed.unanalyzedCategory = nil
	return &withoutUnanalyzed
}

func mergeCapabilityMap(dst, s1, s2 map[string]cpb.Capability) {
	for k, v := range s1 {
		dst[k] = v
	}
	for k, v := range s2 {
		dst[k] = v
	}
}

// LoadClassifier returns a capability classifier loaded from the specified
// io.Reader. The filename argument is used only for providing context to
// error messages. The classifier will also include the default Capslock
// classifications unless the excludeBuiltin argument is set.
//
// Refer to the interesting/interesting.cm file in the source code for an
// example of the capability map format. Classifications loaded from a
// caller-specified file always override builtin classifications.
func LoadClassifier(source string, r io.Reader, excludeBuiltin bool) (*Classifier, error) {
	userClassifier, err := parseCapabilityMap(source, r)
	if err != nil {
		return nil, err
	}
	if excludeBuiltin {
		return userClassifier, nil
	}
	ret := newClassifier()
	// Merge.
	// TODO(djm): use `maps.Copy` once it graduates from x/exp.
	mergeCapabilityMap(ret.functionCategory, internalMap.functionCategory, userClassifier.functionCategory)
	mergeCapabilityMap(ret.unanalyzedCategory, internalMap.unanalyzedCategory, userClassifier.unanalyzedCategory)
	mergeCapabilityMap(ret.packageCategory, internalMap.packageCategory, userClassifier.packageCategory)
	for k, v := range internalMap.ignoredEdges {
		ret.ignoredEdges[k] = v
	}
	for k, v := range userClassifier.ignoredEdges {
		ret.ignoredEdges[k] = v
	}
	cgoSuffixes := map[string]bool{}
	for _, v := range internalMap.cgoSuffixes {
		cgoSuffixes[v] = true
	}
	for _, v := range userClassifier.cgoSuffixes {
		cgoSuffixes[v] = true
	}
	// TODO(djm) use `maps.Keys` once it graduates from x/exp.
	for k := range cgoSuffixes {
		ret.cgoSuffixes = append(ret.cgoSuffixes, k)
	}
	sort.Strings(ret.cgoSuffixes)
	return ret, nil
}

// IncludeCall returns true if a call from one function to another should be
// considered when searching for transitive capabilities.  We return false for
// some internal calls in the standard library where we know a potential
// transitive capability does not arise in practice.
func (c *Classifier) IncludeCall(caller, callee string) bool {
	_, ok := internalMap.ignoredEdges[[2]string{caller, callee}]
	return !ok
}

// FunctionCategory returns a Category for the given function specified by
// a package name and function name.  Examples of function names include
// "math.Cos", "(time.Time).Clock", and "(*sync.Cond).Signal".
//
// If the return value is Unspecified, then we have not declared it to be
// either safe or unsafe, so its descendants will have to be considered by the
// static analysis.
func (c *Classifier) FunctionCategory(pkg, name string) cpb.Capability {
	for _, s := range c.cgoSuffixes {
		// Calls to C functions produce a call to a function
		// named "_cgo_runtime_cgocall" in the current package.
		// Calls to the various type conversion functions in the
		// "C" pseudo-package (see See https://pkg.go.dev/cmd/cgo)
		// produce calls to other functions listed in cgoSuffixes.
		if strings.HasSuffix(name, s) {
			return cpb.Capability_CAPABILITY_CGO
		}
	}
	if cat, ok := c.functionCategory[name]; ok {
		// If the function has a category, that takes precedence over its
		// package's category.  This includes the possibility that the function
		// is categorized as "unspecified", which indicates that the analyzer
		// should analyze the function's code as normal.
		return cat
	}
	if cat, ok := c.unanalyzedCategory[name]; ok {
		return cat
	}
	return c.packageCategory[pkg]
}
