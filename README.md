![capslock](docs/capslock-banner.png)

Capslock is a capability analysis CLI for Go packages that informs users of
which privileged operations a given package can access. This works by
classifying the **capabilities** of Go packages by following transitive calls to privileged
standard library operations.

The recent increase in supply chain attacks targeting open source software
has highlighted that third party dependencies should not be inherently trusted.
Capabilities indicate what permissions a package has access to, and can be used
in conjunction with other security signals to indicate which code requires
additional scrutiny before it can be considered trusted.

## What are capabilities?

Current security analysis focuses a lot on identifying vulnerabilities in
packages -- an important goal given the rate of new CVEs being identified.
To complement this analysis, we are alerting on the capabilities of packages,
meaning that we are identifying what permissions the package has access to via
its transitive dependencies on standard library functions with privileged
accesses.

This has many potential applications, from identifying the purpose of packages
by looking at what capabilities they use, to directing security reviews to more
privileged code paths, and even alerting on unexpected capability changes to
stop potential supply chain threats before they can become an issue.

This is motivated by the Principle of Least Privilege -- the idea that access
should be limited to the minimal set that is feasible and practical. We intend
to apply this to software development to ensure that code can be scoped to the
minimal set of capabilities that are required to perform its intended purpose.

To learn more about the capabilities in your dependencies, install Capslock

``` shell
go install github.com/google/capslock/cmd/capslock@latest
```

You can then invoke Capslock by running `capslock` from the path of the packages you want to analyze.

## Caveats

See the [caveats](docs/caveats.md) file.

## Contributing

See the [contributing](CONTRIBUTING.md) file.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=google/capslock&type=Date)](https://star-history.com/#google/capslock&Date)
