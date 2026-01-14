#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build_putty_relwithdebuginfo.sh [--clear] [--build-dir DIR] [--jobs N] [--target NAME]...

Builds PuTTY from ./PuTTY using CMake with CMAKE_BUILD_TYPE=RelWithDebInfo.

Defaults:
  --build-dir  PuTTY/build-relwithdebuginfo
  --jobs       nproc
  --target     putty --target pterm

Examples:
  ./build_putty_relwithdebuginfo.sh
  ./build_putty_relwithdebuginfo.sh --clear
  ./build_putty_relwithdebuginfo.sh --target putty
  ./build_putty_relwithdebuginfo.sh --build-dir /tmp/putty-relwithdebuginfo
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
putty_src="${script_dir}"

if [[ ! -f "${putty_src}/CMakeLists.txt" ]]; then
  echo "fail: ${putty_src}/CMakeLists.txt not found" >&2
  exit 2
fi

build_dir="${putty_src}/build-relwithdebuginfo"
jobs="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
clear=0
declare -a targets=()
targets_were_default=0

filter_putty_manpage_warnings() {
  awk '
    BEGIN { skip = 0 }
    skip == 0 && $0 ~ /^CMake Warning at .*cmake\/platforms\/unix\.cmake:232/ { skip = 1; next }
    skip == 1 {
      if ($0 ~ /^$/) { skip = 0; next }
      next
    }
    { print }
  '
}

run_cmake_filtered() {
  set +o pipefail
  "$@" 2>&1 | filter_putty_manpage_warnings
  local rc="${PIPESTATUS[0]}"
  set -o pipefail
  return "${rc}"
}

escape_ere() {
  sed -e 's/[][(){}.^$*+?|\\/]/\\&/g' <<<"$1"
}

target_is_available() {
  local available_targets="$1"
  local target="$2"
  local escaped
  escaped="$(escape_ere "${target}")"
  grep -Eq "^(\\.\\.\\. )?${escaped}(:|[[:space:]]|$)" <<<"${available_targets}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --clean|--clear|-clear)
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
    --target)
      [[ $# -ge 2 ]] || { echo "fail: --target requires a value" >&2; exit 2; }
      targets+=("$2")
      shift 2
      ;;
    *)
      echo "fail: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${#targets[@]} -eq 0 ]]; then
  targets=(putty pterm)
  targets_were_default=1
fi

command -v cmake >/dev/null 2>&1 || { echo "fail: cmake not found in PATH" >&2; exit 2; }
command -v cc >/dev/null 2>&1 || { echo "fail: c compiler (cc) not found in PATH" >&2; exit 2; }

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "warn: pkg-config not found; cmake may fail to detect gtk/x11" >&2
else
  if ! pkg-config --exists gtk+-3.0; then
    echo "warn: gtk+-3.0 not found via pkg-config; putty/pterm targets may not be available" >&2
    echo "      on centos/rhel: install gtk3-devel, libX11-devel, libXext-devel, libXrandr-devel" >&2
  fi
fi

if [[ "${clear}" -eq 1 ]]; then
  rm -rf "${build_dir}"
fi

generator_args=()
if command -v ninja >/dev/null 2>&1; then
  generator_args=(-G Ninja)
fi

run_cmake_filtered cmake "${generator_args[@]}" \
  -S "${putty_src}" \
  -B "${build_dir}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

available_targets=""
if [[ -f "${build_dir}/build.ninja" ]] && command -v ninja >/dev/null 2>&1; then
  available_targets="$(ninja -C "${build_dir}" -t targets all 2>/dev/null || true)"
else
  available_targets="$(run_cmake_filtered cmake --build "${build_dir}" --target help)"
fi
declare -a missing_targets=()
declare -a present_targets=()
for t in "${targets[@]}"; do
  if target_is_available "${available_targets}" "${t}"; then
    present_targets+=("${t}")
  else
    missing_targets+=("${t}")
  fi
done

build_all=0
if [[ ${#missing_targets[@]} -ne 0 ]]; then
  if [[ "${targets_were_default}" -eq 1 ]]; then
    echo "warn: default targets not available: ${missing_targets[*]}" >&2
    echo "      building default 'all' target instead" >&2
    build_all=1
  else
    echo "fail: requested targets not available: ${missing_targets[*]}" >&2
    echo "      run: cmake --build \"${build_dir}\" --target help" >&2
    exit 2
  fi
fi

if [[ "${build_all}" -eq 1 ]]; then
  run_cmake_filtered cmake --build "${build_dir}" -- -j "${jobs}"
  echo "built default target: all"
else
  targets=("${present_targets[@]}")
  run_cmake_filtered cmake --build "${build_dir}" --target "${targets[@]}" -- -j "${jobs}"
  echo "built targets: ${targets[*]}"
fi

for t in "${targets[@]}"; do
  if [[ -x "${build_dir}/${t}" ]]; then
    echo "bin: ${build_dir}/${t}"
  fi
done
