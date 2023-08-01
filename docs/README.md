# Using Capslock

Install the Capslock command-line tool with the
[go tool](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies):

``` shell
go install github.com/google/capslock/cmd/capslock@latest
```

Capslock can analyze packages that are part of your current module, or are
dependencies of your current module.
If necessary, use `go get` to make the package you wish to analyze a dependency
of your current module.

``` shell
go get package/to/analyze
capslock -packages package/to/analyze
```

If the package you wish to analyze isn't available you will get an error
telling you to `go get` the package. You can also run `capslock` directly
from the path of the package you want to analyze without needing to specify
the `-packages` flag.

If `capslock` isn't found or doesn't work, run `ls $GOBIN` to check that the
capslock binary was installed properly and `which capslock` to check where the
binary was installed.
See the
[go command documentation](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies)
for more information about installing go packages.

There are several output formats you can use in Capslock using the `-output`
flag. For example, use `-output=v` to get more verbose output that includes
example callpaths for all identified capabilities, or `-output=json` for json
output enumerating each function with a capability that was identified by the
analyzer, with an example call path for each one demonstrating that capability.


## List of capabilities

See [capabilities documentation](capabilities.md) for a list of the capabilities the tool reports.

## Interpreting capability reports

For many reports, the capabilities are unsurprising.  A library which connects
to a service over the internet would be expected to have the `NETWORK`
capability.

For other reports, the practical consequences can be less clear.  For example,
most uses of the `reflect` package have a simple purpose such as reading fields
from a value with an arbitrary struct type.  But `reflect` can also be used to
invoke arbitrary functions.  The static analysis is unable to determine the
behavior of all code using reflect, so it falls back to reporting to the user
that the code has the `REFLECT` capability.  Users can then inspect the
functions the analysis points to if they wish.

## Flags

Other than the `-packages` flag for setting the path for the packages to
analyze, there are several other options for running Capslock.

### `-output`

The `-output` flag lets you select what level of detail and format you want the
output to be in. If the provided flag doesn't match any of the options, it
defaults to give a short human-readable report on what the list of identified
capabilities are.

Accepted values for this flag include:

1. `v` or `verbose` for a longer human-readable output including example
   callpaths.
1. `j` or `json` for a machine-readable json output including paths to all
   capabilities.
1. `compare` plus an additional argument specifying the location of a capability
   file. This requires that you have already run Capslock on a previous version
   of the package, and written the output in json format to a file - passing the
   file location with this flags lets you identify which of the capabilities
   changed between package version.

### Other flags

1. `-noisy` will expand the analysis of functions with `CAPABILITY_UNANALYZED`
   to report the possible capabilities of these functions. Can result in
   spurious capabilities.
1. `-template` allows you to specify an alternative template for printing the
   output.
1. `-goos` and `-goarch` allow you to set to GOOS and GOARCH values for use when
   loading packages.
1. `-buildtags` is used for setting build tags that are used in loading
   packages.

