[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/linux.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Alinux)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/osx.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Aosx)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/windows.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Awindows)
[![Coverage Status](https://coveralls.io/repos/github/heimdal/heimdal/badge.svg?branch=master)](https://coveralls.io/github/heimdal/heimdal?branch=master)

Heimdal
=======

Heimdal is an implementation of:

 - PKIX, and
 - Kerberos.

Heimdal uses the separate `asn1_compile` project for its schema compiler and
generic DER/BER support library.  Build and install `asn1_compile` 0.1.0 or
newer first; Heimdal discovers `libasn1` with `pkg-config` and uses the native
`asn1_compile` program to generate the protocol codecs owned by each Heimdal
library.  A non-standard installation can be selected with
`--with-asn1-prefix=/path` or `--with-asn1-compiler=/path/asn1_compile`.

For cross compilation, install a native `asn1_compile` program for the build
machine and a target `libasn1`; pass the native program explicitly when it is
not on `PATH`.  Heimdal release archives do not bundle either component.
The ownership and ABI changes are described in
[`doc/asn1-migration.md`](doc/asn1-migration.md).

For information how to install see [here](https://github.com/heimdal/heimdal/wiki/Building-and-installing).

There are man pages for most of the commands.

Bug reports and bugs are appreciated.  Use [GitHub issues](https://www.heimdal.software/heimdal/issues).

For more information see the project homepage [https://heimdal.software/heimdal/](https://heimdal.software/heimdal/) or the mailing lists:

  heimdal-announce@heimdal.software	low-volume announcement
  heimdal-discuss@heimdal.software	high-volume discussion

send mail to [heimdal-announce-subscribe@heimdal.software](mailto:heimdal-announce-subscribe@heimdal.software) and
[heimdal-discuss-subscribe@heimdal.software](mailto:heimdal-discuss-subscribe@heimdal.software)
respectively to subscribe.


Build Status
============

[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/linux.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Alinux)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/osx.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Aosx)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/windows.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Awindows)
[![Coverage Status](https://coveralls.io/repos/github/heimdal/heimdal/badge.svg?branch=master)](https://coveralls.io/github/heimdal/heimdal?branch=master)
