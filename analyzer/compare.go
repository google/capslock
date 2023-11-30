// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"fmt"
	"go/types"
	"os"
	"sort"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/encoding/protojson"
)

func compare(baselineFilename string, pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) error {
	compareData, err := os.ReadFile(baselineFilename)
	if err != nil {
		return fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from reading comparison file: %v", programName(), err.Error())
	}
	baseline := new(cpb.CapabilityInfoList)
	err = protojson.Unmarshal(compareData, baseline)
	if err != nil {
		return fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from parsing comparison file: %v", programName(), err.Error())
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, config)
	diffCapabilityInfoLists(baseline, cil)
	return nil
}

type capabilitySet map[cpb.Capability]*cpb.CapabilityInfo
type capabilitiesMap map[string]capabilitySet

// populateMap takes a CapabilityInfoList and returns a map from package
// directory and capability to a pointer to the corresponding entry in the
// input.
func populateMap(cil *cpb.CapabilityInfoList) capabilitiesMap {
	m := make(capabilitiesMap)
	for _, ci := range cil.GetCapabilityInfo() {
		dir := ci.GetPackageDir()
		capmap := m[dir]
		if capmap == nil {
			capmap = make(capabilitySet)
			m[dir] = capmap
		}
		capmap[ci.GetCapability()] = ci
	}
	return m
}

func diffCapabilityInfoLists(baseline, current *cpb.CapabilityInfoList) {
	baselineMap := populateMap(baseline)
	currentMap := populateMap(current)
	var packages []string
	for packageName := range baselineMap {
		packages = append(packages, packageName)
	}
	for packageName := range currentMap {
		if _, ok := baselineMap[packageName]; !ok {
			packages = append(packages, packageName)
		}
	}
	sort.Strings(packages)
	var differenceFound bool
	for _, packageName := range packages {
		b := baselineMap[packageName]
		c := currentMap[packageName]
		for capability := range c {
			if _, ok := b[capability]; !ok {
				differenceFound = true
				fmt.Printf("Package %s has new capability %s compared to the baseline.\n",
					packageName, capability)
			}
		}
		for capability := range b {
			if _, ok := c[capability]; !ok {
				differenceFound = true
				fmt.Printf("Package %s no longer has capability %s which was in the baseline.\n",
					packageName, capability)
			}
		}
	}
	if differenceFound {
		os.Exit(1)
	}
	os.Exit(0)
}
