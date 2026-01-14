#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: run_new_tests.sh [--clear] [--build-dir DIR] [--jobs N]

Builds (RelWithDebInfo) and runs the newly added PuTTY tests.

Defaults:
  --build-dir  ./build-relwithdebuginfo
  --jobs       nproc

Examples:
  ./run_new_tests.sh
  ./run_new_tests.sh --clear
  ./run_new_tests.sh --build-dir /tmp/putty-relwithdebuginfo
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${script_dir}/build-relwithdebuginfo"
jobs="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
clear=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --clear|-clear)
      clear=1
      shift
      ;;
    --build-dir)
      [[ $# -ge 2 ]] || { echo "fail: --build-dir requires a value" >&2; exit 2; }
      build_dir="$2"
      shift 2
      ;;
    --jobs)
      [[ $# -ge 2 ]] || { echo "fail: --jobs requires a value" >&2; exit 2; }
      jobs="$2"
      shift 2
      ;;
    *)
      echo "fail: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

build_args=(--build-dir "${build_dir}" --jobs "${jobs}" --target test_sessionlog_processing)
if [[ "${clear}" -eq 1 ]]; then
  build_args=(--clear "${build_args[@]}")
fi

"${script_dir}/build_putty_relwithdebuginfo.sh" "${build_args[@]}"

test_bin="${build_dir}/test_sessionlog_processing"
if [[ ! -x "${test_bin}" ]]; then
  echo "fail: test binary not found: ${test_bin}" >&2
  exit 1
fi

exec "${test_bin}"

