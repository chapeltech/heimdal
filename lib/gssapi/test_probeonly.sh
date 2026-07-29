#!/bin/sh

set -eu

config="${TMPDIR:-/tmp}/heimdal-probeonly-config.$$"
trace="${TMPDIR:-/tmp}/heimdal-probeonly-trace.$$"
expected="${TMPDIR:-/tmp}/heimdal-probeonly-expected.$$"
trap 'rm -f "$config" "$trace" "$expected"' EXIT HUP INT TERM

cat >"$config" <<EOF
probe-first 1.3.6.1.4.1.5322.26.2 $PWD/.libs/test_probe_first_mech.so -
probe-second 1.3.6.1.4.1.5322.26.3 $PWD/.libs/test_probe_second_mech.so -
:builtin sanon
:builtin spnego
EOF

cat >"$expected" <<EOF
first normal
second probe
EOF

GSS_MECH_CONFIG="$config" PROBEONLY_TRACE="$trace" ./test_probeonly
cmp "$expected" "$trace"
