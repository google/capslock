// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"embed"
	"fmt"
	"go/types"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed static/*
var staticContent embed.FS

func RunCapslock(args []string, output string, pkgs []*packages.Package, queriedPackages map[*types.Package]struct{},
	config *Config) error {
	if output == "compare" {
		if len(args) != 1 {
			return fmt.Errorf("Usage: %s -output=compare <filename>; provided %v args", programName(), len(args))
		}
		compare(args[0], pkgs, queriedPackages, config)
	} else if len(args) >= 1 {
		return fmt.Errorf("%s: unknown command", args)
	}
	templateFuncMap := template.FuncMap{
		"format": templateFormat,
	}
	if output == "json" || output == "j" {
		cil := GetCapabilityInfo(pkgs, queriedPackages, config)
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(cil)
		if err != nil {
			return fmt.Errorf("internal error: couldn't marshal protocol buffer: %s", err.Error())
		}
		fmt.Println(string(b))
		return nil
	} else if output == "m" || output == "machine" {
		var cs []string
		cil := GetCapabilityCounts(pkgs, queriedPackages, config)
		for c := range cil.CapabilityCounts {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		for _, c := range cs {
			fmt.Println(c)
		}
		return nil
	} else if output == "v" || output == "verbose" {
		cil := GetCapabilityStats(pkgs, queriedPackages, config)
		ctm := template.Must(template.New("verbose.tmpl").Funcs(templateFuncMap).ParseFS(staticContent, "static/verbose.tmpl"))
		return ctm.Execute(os.Stdout, cil)
	} else if output == "g" || output == "graph" {
		return graphOutput(pkgs, queriedPackages, config)
	}
	cil := GetCapabilityCounts(pkgs, queriedPackages, config)
	ctm := template.Must(template.New("default.tmpl").Funcs(templateFuncMap).ParseFS(staticContent, "static/default.tmpl"))
	return ctm.Execute(os.Stdout, cil)
}

func templateFormat(args ...interface{}) string {
	var format string
	if len(args) != 0 {
		format = args[0].(string)
	}
	var w strings.Builder
	switch format {
	case "":
		// "{{format}}" without arguments resets format.
		color.New(color.FgHiBlack).UnsetWriter(&w)
	case "intro", "callpath", "callpath-site":
		color.New(color.FgHiBlack).SetWriter(&w)
	case "highlight":
		color.New(color.FgCyan).SetWriter(&w)
	case "heading":
		color.New(color.FgHiWhite).SetWriter(&w)
	case "nocap":
		color.New(color.FgHiGreen).SetWriter(&w)
	case "capability":
		var capability string
		if s, ok := args[1].(fmt.Stringer); ok {
			capability = s.String()
		} else {
			capability, ok = args[1].(string)
		}
		switch capability {
		case "CAPABILITY_SAFE":
			color.New(color.FgHiGreen).SetWriter(&w)
		case "CAPABILITY_ARBITRARY_EXECUTION", "CAPABILITY_CGO", "CAPABILITY_UNSAFE_POINTER", "CAPABILITY_EXEC":
			color.New(color.FgHiRed).SetWriter(&w)
		default:
			color.New(color.FgHiYellow).SetWriter(&w)
		}
	}
	return w.String()
}
