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
	"text/tabwriter"

	cpb "github.com/google/capslock/proto"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/encoding/protojson"
)

// granularity determines the kind of comparison done by compare.
type granularity int8

const (
	granularityPackage  granularity = iota // compare capabilities per package
	granularityFunction                    // compare capabilities per function
)

func granularityFromString(g string) (granularity, error) {
	switch g {
	case "package":
		return granularityPackage, nil
	case "function":
		return granularityFunction, nil
	default:
		return 0, fmt.Errorf("unknown granularity: %q", g)
	}
}

func compare(baselineFilename string, pkgs []*packages.Package, queriedPackages map[*types.Package]struct{}, config *Config) (different bool, err error) {
	g, err := granularityFromString(config.Granularity)
	if err != nil {
		return false, err
	}
	compareData, err := os.ReadFile(baselineFilename)
	if err != nil {
		return false, fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from reading comparison file: %v", programName(), err.Error())
	}
	baseline := new(cpb.CapabilityInfoList)
	err = protojson.Unmarshal(compareData, baseline)
	if err != nil {
		return false, fmt.Errorf("Comparison file should include output from running `%s -output=j`. Error from parsing comparison file: %v", programName(), err.Error())
	}
	cil := GetCapabilityInfo(pkgs, queriedPackages, config)
	return diffCapabilityInfoLists(baseline, cil, g), nil
}

type mapKey struct {
	key        string
	capability cpb.Capability
}
type capabilitiesMap map[mapKey]*cpb.CapabilityInfo

// populateMap takes a CapabilityInfoList and returns a map from package
// or function and capability to a pointer to the corresponding entry in the
// input.
func populateMap(cil *cpb.CapabilityInfoList, g granularity) capabilitiesMap {
	m := make(capabilitiesMap)
	for _, ci := range cil.GetCapabilityInfo() {
		mk := mapKey{capability: ci.GetCapability()}
		// The calculation of mk.key depends on the desired granularity.
		switch g {
		case granularityPackage:
			mk.key = ci.GetPackageDir()
			m[mk] = ci
		case granularityFunction:
			if len(ci.Path) == 0 {
				break
			}
			mk.key = ci.Path[0].GetName()
			if mk.key != "" {
				m[mk] = ci
			}
		}
	}
	return m
}

func diffCapabilityInfoLists(baseline, current *cpb.CapabilityInfoList, g granularity) (different bool) {
	baselineMap := populateMap(baseline, g)
	currentMap := populateMap(current, g)
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
	for _, key := range keys {
		ciBaseline, inBaseline := baselineMap[key]
		ciCurrent, inCurrent := currentMap[key]
		if !inBaseline && inCurrent {
			if different {
				fmt.Println()
			}
			different = true
			fmt.Printf("Package %s has new capability %s compared to the baseline.\n",
				key.key, key.capability)
			printCallPath(ciCurrent.Path)
		}
		if inBaseline && !inCurrent {
			if different {
				fmt.Println()
			}
			different = true
			fmt.Printf("Package %s no longer has capability %s which was in the baseline.\n",
				key.key, key.capability)
			printCallPath(ciBaseline.Path)
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
