#!/bin/sh

set -eu

usage()
{
    echo "usage: $0 BUILD_ROOT SOURCE_ROOT [LIBRARY ABI_VERSION_DIR ...]" >&2
    exit 1
}

platform()
{
    if [ -n "${ABI_PLATFORM:-}" ]; then
        echo "$ABI_PLATFORM"
        return
    fi

    if command -v cc >/dev/null 2>&1; then
        cc -dumpmachine 2>/dev/null && return
    fi

    echo "$(uname -m)-$(uname -s | tr '[:upper:]' '[:lower:]')"
}

library_name()
{
    echo "$1" | sed 's/\.so\..*/.so/'
}

baseline_soname()
{
    sed -n "s/.*soname='\([^']*\)'.*/\1/p" "$1" | sed -n '1p'
}

library_soname()
{
    readelf -d "$1" 2>/dev/null |
        sed -n 's/.*Library soname: \[\(.*\)\].*/\1/p' |
        sed -n '1p'
}

built_library()
{
    find "$build_root/lib" \( \
        -path "*/.libs/$1" -type f -o \
        -path "*/.libs/$1" -type l \
    \) |
        sort |
        sed -n '1p'
}

expected_soname()
{
    echo "$1.$(basename "$2")"
}

added_binaries_args()
{
    if ! abidiff --help 2>&1 | grep -q -- '--added-binaries-dir2'; then
        return
    fi

    find "$build_root/lib" -type d -name .libs |
        sort |
        sed 's/^/--added-binaries-dir2 /'
}

write_report_header()
{
    report=$1

    {
        echo "baseline: $baseline"
        echo "baseline soname: $soname"
        echo "current: $current"
        echo "current soname: ${current_soname:-unknown}"
        echo "build root: $build_root"
        echo "source root: $source_root"
        echo "platform: $abi_platform"
        echo
    } > "$report"
}

run_abidiff()
{
    report=$1
    shift

    write_report_header "$report"

    set +e
    abidiff \
        --no-added-syms \
        --headers-dir2 "$headers_dir" \
        $added_binaries \
        "$@" \
        "$baseline" \
        "$current" \
        >> "$report" 2>&1
    rc=$?
    set -e

    return "$rc"
}

check_abi()
{
    library=$1
    abi_dir=$2
    soname=$(expected_soname "$library" "$abi_dir")
    baseline="$abi_dir/$abi_platform.abi"

    if [ -n "${ABI_REPORT_DIR:-}" ]; then
        report_dir="$ABI_REPORT_DIR/$soname"
    else
        report_dir="$build_root/abi-reports/$soname"
    fi
    raw_report="$report_dir/$abi_platform.raw.abidiff"
    filtered_report="$report_dir/$abi_platform.abidiff"

    mkdir -p "$report_dir"

    if [ -f "$abi_dir/skip" ]; then
        {
            echo "ABI skipped: $soname"
            cat "$abi_dir/skip"
        } | tee "$filtered_report" > "$raw_report"
        echo "ABI skipped: $soname"
        return
    fi

    if [ ! -f "$baseline" ]; then
        echo "$0: ABI baseline not found: $baseline" | tee "$filtered_report"
        status=1
        return
    fi

    baseline_soname=$(baseline_soname "$baseline")
    if [ "$baseline_soname" != "$soname" ]; then
        {
            echo "ABI baseline SONAME mismatch for $library"
            echo "baseline: $baseline"
            echo "baseline soname: ${baseline_soname:-unknown}"
            echo "expected soname: $soname"
        } | tee "$filtered_report" > "$raw_report"
        status=1
        return
    fi

    current=$(built_library "$library")
    if [ -z "$current" ]; then
        echo "missing built library: $library" |
            tee "$filtered_report"
        status=1
        return
    fi

    current_soname=$(library_soname "$current")
    if [ "$current_soname" != "$soname" ]; then
        {
            echo "ABI SONAME mismatch for $library"
            echo "baseline: $baseline"
            echo "baseline soname: $soname"
            echo "current: $current"
            echo "current soname: ${current_soname:-unknown}"
            echo
            echo "The ABI baseline must match the shared library version being built."
        } | tee "$filtered_report" > "$raw_report"
        status=1
        return
    fi

    suppressions="$abi_dir/suppressions.abignore"

    raw_status=0
    if run_abidiff "$raw_report"; then
        echo "ABI raw ok: $soname"
    else
        raw_status=$?
        echo "ABI raw differs: $soname"
    fi

    if [ -f "$suppressions" ] && grep -q '^\[' "$suppressions"; then
        if run_abidiff "$filtered_report" --suppressions "$suppressions"; then
            echo "ABI ok: $soname"
        else
            cat "$filtered_report"
            echo "ABI differences found for $soname" >&2
            status=1
        fi
    else
        cp "$raw_report" "$filtered_report"
        if [ "$raw_status" -ne 0 ]; then
            cat "$filtered_report"
            echo "ABI differences found for $soname" >&2
            status=1
        else
            echo "ABI ok: $soname"
        fi
    fi
}

if [ "$#" -lt 2 ]; then
    usage
fi

build_root=$1
source_root=$2
shift 2

if [ ! -d "$build_root/lib" ]; then
    echo "$0: build lib directory not found: $build_root/lib" >&2
    exit 1
fi

if [ ! -d "$source_root/lib" ]; then
    echo "$0: source lib directory not found: $source_root/lib" >&2
    exit 1
fi

headers_dir="$build_root/include"
if [ ! -d "$headers_dir" ]; then
    headers_dir="$source_root/include"
fi
if [ ! -d "$headers_dir" ]; then
    echo "$0: include directory not found in build or source tree" >&2
    exit 1
fi

abi_platform=$(platform)
added_binaries=$(added_binaries_args)
status=0

if [ "$#" -eq 0 ]; then
    candidates=$(find "$source_root/lib" -path "*/abi/*" -name "$abi_platform.abi" -type f | sort)
    selected=
    seen=

    for candidate in $candidates; do
        abi_dir=$(dirname "$candidate")
        soname=$(baseline_soname "$candidate")
        if [ -z "$soname" ]; then
            echo "$0: ABI baseline has no SONAME: $candidate" >&2
            status=1
            continue
        fi

        library=$(library_name "$soname")
        case " $seen " in
        *" $library "*) continue ;;
        esac
        seen="$seen $library"

        if [ -f "$abi_dir/skip" ]; then
            selected="$selected $library $abi_dir"
            continue
        fi

        current=$(built_library "$library")
        if [ -z "$current" ]; then
            echo "$0: built library not found for ABI baseline: $library" >&2
            status=1
            continue
        fi

        current_soname=$(library_soname "$current")
        if [ -z "$current_soname" ]; then
            echo "$0: current library has no SONAME: $current" >&2
            status=1
            continue
        fi

        match=
        for possible in $candidates; do
            possible_soname=$(baseline_soname "$possible")
            if [ "$(library_name "$possible_soname")" = "$library" ] &&
                [ "$possible_soname" = "$current_soname" ]
            then
                match=$(dirname "$possible")
                break
            fi
        done

        if [ -z "$match" ]; then
            echo "$0: ABI baseline not found for built $current_soname" >&2
            status=1
            continue
        fi

        selected="$selected $library $match"
    done

    set -- $selected
fi

if [ $(($# % 2)) -ne 0 ]; then
    usage
fi

if [ "$#" -eq 0 ]; then
    if [ "$status" -ne 0 ]; then
        exit "$status"
    fi
    echo "$0: no ABI directories found" >&2
    exit 1
fi

while [ "$#" -gt 0 ]; do
    library=$1
    abi_dir=$2
    shift 2

    check_abi "$library" "$abi_dir"
done

exit "$status"
