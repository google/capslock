// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"go/types"
	"os"
	"path"
	"sort"
	"sync"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/proto"
)

var (
	standardLibraryPackagesOnce sync.Once
	standardLibraryPackagesMap  map[string]struct{}
)

// LoadConfig specifies the build tags, GOOS value, and GOARCH value to use
// when loading packages.  These will be used to determine when a file's build
// constraint is satisfied.  See
// https://pkg.go.dev/cmd/go#hdr-Build_constraints for more information.
type LoadConfig struct {
	BuildTags string
	GOOS      string
	GOARCH    string
}

// PackagesLoadModeNeeded is a packages.LoadMode that has all the bits set for
// the information that this package uses to perform its analysis.  Users
// should load packages for analysis using this LoadMode (or a superset.)
const PackagesLoadModeNeeded packages.LoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

// GetQueriedPackages builds a set of *types.Package matching the input query so that
// we can limit the output to only functions in these packages, not
// their dependencies too.
func GetQueriedPackages(pkgs []*packages.Package) map[*types.Package]struct{} {
	queriedPackages := map[*types.Package]struct{}{}
	for _, p := range pkgs {
		queriedPackages[p.Types] = struct{}{}
	}
	return queriedPackages
}

func LoadPackages(packageNames []string, lcfg LoadConfig) ([]*packages.Package, error) {
	cfg := &packages.Config{Mode: PackagesLoadModeNeeded}
	if lcfg.BuildTags != "" {
		cfg.BuildFlags = []string{"-tags=" + lcfg.BuildTags}
	}
	if lcfg.GOOS != "" || lcfg.GOARCH != "" {
		env := append([]string(nil), os.Environ()...) // go1.21 has slices.Clone for this
		if lcfg.GOOS != "" {
			env = append(env, "GOOS="+lcfg.GOOS)
		}
		if lcfg.GOARCH != "" {
			env = append(env, "GOARCH="+lcfg.GOARCH)
		}
		cfg.Env = env
	}
	return packages.Load(cfg, packageNames...)
}

func standardLibraryPackages() map[string]struct{} {
	standardLibraryPackagesOnce.Do(func() {
		pkgs, err := packages.Load(nil, "std")
		if err != nil {
			panic(err.Error())
		}
		standardLibraryPackagesMap = make(map[string]struct{})
		for _, p := range pkgs {
			standardLibraryPackagesMap[p.PkgPath] = struct{}{}
		}
	})
	return standardLibraryPackagesMap
}

func collectModuleInfo(pkgs []*packages.Package) []*cpb.ModuleInfo {
	pathToModule := make(map[string]*cpb.ModuleInfo)
	forEachPackageIncludingDependencies(pkgs, func(pkg *packages.Package) {
		m := pkg.Module
		if m == nil || m.Path == "" || m.Version == "" {
			// No module information.
			return
		}
		if _, ok := pathToModule[m.Path]; ok {
			// We've seen this module.
			return
		}
		pm := new(cpb.ModuleInfo)
		pm.Path = proto.String(m.Path)
		pm.Version = proto.String(m.Version)
		pathToModule[m.Path] = pm
	})
	// Sort by path.
	var modulePaths []string
	for path := range pathToModule {
		modulePaths = append(modulePaths, path)
	}
	sort.Strings(modulePaths)
	// Construct the output slice.
	var modules []*cpb.ModuleInfo
	for _, path := range modulePaths {
		modules = append(modules, pathToModule[path])
	}
	return modules
}

func collectPackageInfo(pkgs []*packages.Package) []*cpb.PackageInfo {
	var out []*cpb.PackageInfo
	std := standardLibraryPackages()
	forEachPackageIncludingDependencies(pkgs, func(pkg *packages.Package) {
		if _, ok := std[pkg.PkgPath]; ok {
			// Skip this package since it is part of the Go standard library.
			return
		}
		pi := new(cpb.PackageInfo)
		pi.Path = proto.String(pkg.PkgPath)
		for _, i := range pkg.IgnoredFiles {
			pi.IgnoredFiles = append(pi.IgnoredFiles, path.Base(i))
		}
		out = append(out, pi)
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].GetPath() < out[j].GetPath()
	})
	return out
}
