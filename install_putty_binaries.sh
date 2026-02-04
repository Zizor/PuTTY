#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: install_putty_binaries.sh --dest-dir DIR [--from DIR] [--dry-run]

Copies PuTTY build outputs from a previously built CMake build directory into a user-defined folder.

Installs a fixed set of production binaries:
  pageant plink pscp psftp psocks psusan pterm ptermapp putty puttyapp puttygen puttytel

Defaults:
  --from       ./build

Examples:
  ./install_putty_binaries.sh --dest-dir /tmp/putty-bin
  ./install_putty_binaries.sh --from /tmp/putty-build --dest-dir ./out/bin
  ./install_putty_binaries.sh --dest-dir ./out/bin --dry-run
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="${script_dir}"

from_dir="${root_dir}/build"
dest_dir=""
dry_run=0

readonly required_binaries=(
  pageant
  plink
  pscp
  psftp
  psocks
  psusan
  pterm
  ptermapp
  putty
  puttyapp
  puttygen
  puttytel
)

is_installable_elf_executable() {
  local path="$1"
  local name
  name="$(basename "${path}")"

  [[ -f "${path}" ]] || return 1
  [[ -x "${path}" ]] || return 1
  file -b "${path}" | grep -qE '^ELF .* executable'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --from|--from-dir)
      [[ $# -ge 2 ]] || { echo "fail: --from requires a value" >&2; exit 2; }
      from_dir="$2"
      shift 2
      ;;
    --build-dir)
      [[ $# -ge 2 ]] || { echo "fail: --build-dir requires a value" >&2; exit 2; }
      from_dir="$2"
      shift 2
      ;;
    --dest-dir)
      [[ $# -ge 2 ]] || { echo "fail: --dest-dir requires a value" >&2; exit 2; }
      dest_dir="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    *)
      echo "fail: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${dest_dir}" ]]; then
  echo "fail: --dest-dir is required" >&2
  usage >&2
  exit 2
fi

if [[ ! -d "${from_dir}" ]]; then
  echo "fail: from dir not found: ${from_dir}" >&2
  exit 2
fi

command -v file >/dev/null 2>&1 || { echo "fail: file not found in PATH" >&2; exit 2; }
command -v install >/dev/null 2>&1 || { echo "fail: install not found in PATH" >&2; exit 2; }

declare -a missing=()
for name in "${required_binaries[@]}"; do
  path="${from_dir}/${name}"
  if ! is_installable_elf_executable "${path}"; then
    missing+=("${name}")
  fi
done

if [[ ${#missing[@]} -ne 0 ]]; then
  echo "fail: from dir is missing required installable binaries:" >&2
  for name in "${missing[@]}"; do
    echo "  - ${name}" >&2
  done
  if [[ -d "${root_dir}/build-relwithdebuginfo" ]]; then
    echo "hint: if you used build_putty_relwithdebuginfo.sh, try: --from \"${root_dir}/build-relwithdebuginfo\"" >&2
  fi
  exit 2
fi

mkdir -p "${dest_dir}"

echo "installing ${#required_binaries[@]} binaries to: ${dest_dir}" >&2
echo "from dir: ${from_dir}" >&2
echo "required list: ${required_binaries[*]}" >&2
for name in "${required_binaries[@]}"; do
  src="${from_dir}/${name}"
  dst="${dest_dir}/${name}"
  if [[ "${dry_run}" -eq 1 ]]; then
    echo "dry-run: install -m 0755 \"${src}\" \"${dst}\"" >&2
  else
    install -m 0755 "${src}" "${dst}"
  fi
done

echo "done" >&2
echo "note: verify runtime deps with: ldd \"${dest_dir}/<binary>\"" >&2
