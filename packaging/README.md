# Asgard Heimdal packages

This branch owns the private Heimdal packages used by Asgard and its client
software.  The packages install Heimdal below an Asgard-specific prefix so
that they can coexist with the operating system's Kerberos implementation.

The package release identifies the exact upstream source commit in both its
tag and package version.  For example, source commit `e0ee5cada...` is
released as:

```
asgard-20260810.e0ee5cada
```

The corresponding Debian version is
`7.99.1+20260810.e0ee5cada`; the RPM snapshot is
`20260810.e0ee5cada`.

The release workflow must be run from this packaging branch and given an
existing GitHub release tag.  It checks out that tag as the source tree,
builds Debian packages on native amd64 and arm64 runners, builds signed EL9
packages on x86_64, validates their private filesystem layout, and uploads
the packages and `SHA256SUMS` to the existing release.

The packages are build dependencies of other ChapelTech projects.  Consumer
repositories should download a pinned Heimdal release; they must not carry or
modify these package recipes.
