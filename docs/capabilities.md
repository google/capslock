A taxonomy of implied capabilities is central to the Capslock tool's
analysis and reporting. This document describes how these capabilities
are defined, what they represent and how they broadly map to concrete
library calls.

**NB. until the capslock-1.0 release, capability names and mappings are
not stable and are subject to change.** Feedback on the capabilities and
how they are assigned is very welcome.

The capabilities that Capslock reports are defined in the
`src/proto/capability.proto` file, specifically the `Capability`
enum. The `src/interesting/interesting.go` file contains the mappings
from library modules and calls to these capabilities.

Capability mappings are performed first at the *package* level
and then at the *function* level. For example, everything in the
[os](https://pkg.go.dev/os) package is by default assumed to
have the `CAPABILITY_OPERATING_SYSTEM` capability but specific
functions override this with other capabilities, such as the
[os.Chown()](https://pkg.go.dev/os#Chown) function being assigned
`CAPABILITY_FILES`.

In addition to mapping packages and library calls to
capabilites, Capslock may also assign capabilities based
on the use of particular types in the code itself, such as
[unsafe.Pointer](https://pkg.go.dev/unsafe#Pointer) or
[reflect.Value](https://pkg.go.dev/reflect#Value).

## Capabilities

The following section describe the purpose and intent of the
capabilities that Capslock reports in analyzed code. These descriptions
are not meant to be exhaustive.

### CAPABILITY_UNSPECIFIED

This is the default (zero) value for uninitialized capabilities.

It is also explicitly assigned to functions when the module they reside
in has a catch-all capability applied that must be cleared to allow
deeper analysis.

For example, the entire [os/exec](https://pkg.go.dev/os/exec) package
has the catch-all `CAPABILITY_EXEC` capability assigned, but it defines
an internal `exec.wrappedError` type that may wrap another error. Since
the wrapped error may be an arbitrary type that fulfils the `error`
interface , calling into it via `(exec.wrappedError).Error` may invoke
additional capabilities. Clearing the module-level capability with
`CAPABILITY_UNSPECIFIED` allows the analysis to continue and potentially
find these cases.

### CAPABILITY_SAFE

This value is used to explicitly allowlist particular functions or
modules.  Unlike assigning `CAPABILITY_UNSPECIFIED`, assigning this
value explicitly terminates further analysis.

### CAPABILITY_FILES

Represents the ability to read or modify the file system, including
reading or writing files, changing file permissions or ownership,
creating symbolic or hard links, creating or deleting directories and
files.

### CAPABILITY_NETWORK

Represents the ability to interact with the network, including making
connections to other hosts, connecting to local network sockets,
and listening for connections.

### CAPABILITY_RUNTIME

Represents the ability to read or modify sensitive information from the
Go runtime itself. This includes the ability to terminate a goroutine,
change the garbage collector, stack or threading parameters, or change
the runtime's behavior around panicking on memory faults.

### CAPABILITY_READ_SYSTEM_STATE

Represents the ability to read information about the system state and
execution environment, including reading environment variables and their
contents, obtaining a list of available network interfaces and their
addresses, or reading process information such as the current working
directory, process ID or user.

### CAPABILITY_MODIFY_SYSTEM_STATE

Represents the ability to modify the state of the system or execution
environment, such as changing the process' working directory, setting
environment variables, or modifying the disposition of
[os/signal](https://pkg.go.dev/os/signal) handlers.

### CAPABILITY_OPERATING_SYSTEM

This capability acts as a catch-all for operations in the
[os](https://pkg.go.dev/os) package that are not explicitly categorized.

### CAPABILITY_SYSTEM_CALLS

This capability represents the ability to make direct system calls and
is applied at module level to a number of packages. It generally implies
the ability to execute arbitrary code.

### CAPABILITY_ARBITRARY_EXECUTION

Represents the use of operations that invoke assembler code or may
violate Go's type safety (e.g. via the [unsafe](https://pkg.go.dev/unsafe)
package) and thereby may invoke arbitrary behavior. Capslock cannot
effectively analyze such code.

### CAPABILITY_CGO

Identifies calls that execute native code via Go's
[Cgo](https://pkg.go.dev/cmd/cgo) mechanism. Capslock cannot analyze
beyond this boundary.

### CAPABILITY_UNANALYZED

Identifies situations where Capslock could not effectively analyze a
call path due to limitations in the tool itself.

### CAPABILITY_UNSAFE_POINTER

Identifies code that uses `unsafe.Pointer`. This type may be used
to violate Go's type safety and could potentially be used to invoke
arbitrary behavior that Capslock is unable to effectively analyze.

### CAPABILITY_REFLECT

Represents the use of reflection via the
[reflect](https://pkg.go.dev/reflect) package.

### CAPABILITY_EXEC

Represents the ability to execute other programs, e.g. via the
[os/exec](https://pkg.go.dev/os/exec) package.
