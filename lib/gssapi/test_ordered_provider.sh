#!/bin/sh

set -eu

config="${TMPDIR:-/tmp}/heimdal-mech-config.$$"
trace="${TMPDIR:-/tmp}/heimdal-mech-trace.$$"
expected="${TMPDIR:-/tmp}/heimdal-mech-expected.$$"
trap 'rm -f "$config" "$trace" "$expected"' EXIT HUP INT TERM

cat >"$config" <<EOF
decline 1.3.6.1.4.1.5322.26.1 $PWD/.libs/test_ordered_decline_mech.so -
accept 1.3.6.1.4.1.5322.26.1 $PWD/.libs/test_ordered_accept_mech.so -
:builtin spnego
EOF

cat >"$expected" <<EOF
decline init initial
decline accept initial
EOF

GSS_MECH_CONFIG="$config" ORDERED_PROVIDER_TRACE="$trace" \
    PROVIDER_DIRTY_DECLINE=1 ./test_ordered_provider
cmp "$expected" "$trace"

: >"$trace"
cat >"$expected" <<EOF
decline init initial
accept init initial
decline accept initial
accept accept initial
accept init continuation
accept accept continuation
EOF

GSS_MECH_CONFIG="$config" ORDERED_PROVIDER_TRACE="$trace" \
    ./test_ordered_provider
cmp "$expected" "$trace"
