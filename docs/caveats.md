# Caveats

### False Positives

The tool analyzes a library and its dependencies and reports which functions
call, either directly or transitively, standard library functions that have
notable capabilities, such as opening a file or opening a network connection.

However, each chain of calls reported by the tool may not necessarily occur in
practice.  For example, a function may contain an if statement where
[os.ReadFile](https://pkg.go.dev/os#ReadFile) is called if one of the
function's parameters is `true`.  The static analysis assumes that every
block of code within a function might be executed, so any caller of this
function would be reported to have the `FILES` capability via its
dependencies, even if it always passed `false` as the relevant argument.

Similarly, when a method of an interface value is called, the analysis will
determine which runtime types that interface value might have, but this may
include types which do not occur in practice in the chain of function calls
that is reported.

### Reflection

The [reflect](https://pkg.go.dev/reflect) library allows the creation of
objects and types which are difficult for the analysis to follow.  For some
uses of reflect, the analysis can determine that no additional capabilities
are produced.  Otherwise, the tool treats the use of reflect as another
capability and informs the user of it, so that capabilities are not missed
without any indication to the user.

### Calling other programs

The packages [os/exec](https://pkg.go.dev/os/exec) and
[plugin](https://pkg.go.dev/plugin) allow other programs to be loaded
and run.  The analysis cannot determine what capabilities these might have, so
it is reported to the user as a capability of its own.

### Unsafe

Although most uses in practice of the [unsafe](https://pkg.go.dev/unsafe)
library perform simple tasks, it is possible to use unsafe pointers to produce
any behavior at all, by overwriting function pointers or code.  The tool
treats use of unsafe pointers as a capability, and reports them to the user.

### Data Races

Data races on variables of interface and slice type can produce arbitrary
behavior, including calling library functions with any capability, without
needing to use the unsafe library.  The tool does not inform users of writes to
interfaces and slices that may cause a data race.

### go:linkname

Capslock does not resolve the location of functions using a `//go:linkname`
directive,  Calls to such functions will have the `ARBITRARY_EXECUTION`
capability.

See the [compiler
documentation](https://pkg.go.dev/cmd/compile#hdr-Compiler_Directives) for more
information about linkname directives.

### Cgo and Assembly

Capslock cannot analyze C or assembly code.  Capslock will report calls to
[cgo](https://pkg.go.dev/cmd/cgo) or assembly functions by reporting that
the calling functions have the CGO or `ARBITRARY_EXECUTION` capabilities,
respectively.

### Dependency Resolution

Capslock can be used to investigate the capabilities of a library you have
added as a dependency of your project, or which you are considering adding.
When doing this, it is important that the Capslock tool reads the same source
code that the `go` tool will read when building your project.

The best way to achieve this is to run the tool from your project's directory.
This ensures that issues like version selection, vendoring, and module file
directives are resolved in the same way by `capslock` and `go`.

If the library you are considering is not currently a dependency of your
module, you can add it with the `go get` command.

For example:
```sh
$ go get golang.org/x/text/width

$ capslock -packages=golang.org/x/text/width
```

### Build Constraints

Go source files can contain a build constraint, which specifies a condition
determining whether the file should be included in a build.  The constraint is
a boolean expression involving build tags.

See the relevant
[go command documentation](https://pkg.go.dev/cmd/go#hdr-Build_constraints)
for more information about build tags.

The Capslock command-line tool will analyze the same set of files the `go
build` command would.  Extra tags can be specified with the `-buildtags` flag,
equivalent to the `-tags` flag for `go build`.  The `GOOS` and `GOARCH` for the
analysis can also be specified with the `-goos` and `-goarch` flags,
respectively.

### Logic Bugs

Even when a library has the expected set of capabilities, there is of course no
guarantee that it performs its intended task correctly.  A library function
could return incorrect results, or never return at all.

Even with careful human review of all code that is being imported, it can be
difficult to catch logic bugs, especially any that are deliberately hidden.
Some degree of trust in the authors is required for any software that is to be
used for an important purpose.
