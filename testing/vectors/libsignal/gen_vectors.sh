#!/usr/bin/env sh
set -eu

usage() {
	cat <<'EOF'
Usage: gen_vectors.sh [--link] <libsignal_dir> [signal_repo_dir]

Regenerates libsignal-derived X3DH and Double Ratchet vectors.

Arguments:
  libsignal_dir     Path to the libsignal repository checkout.
  signal_repo_dir   Path to this repository (defaults to the script's repo root).

Options:
  --link            Symlink generator sources into libsignal instead of copying.
  -h, --help        Show this help text.

Environment variables:
  LIBSIGNAL_DIR     Same as positional libsignal_dir.
  SIGNAL_DIR        Same as positional signal_repo_dir.
EOF
}

link=0
libsignal_dir="${LIBSIGNAL_DIR:-}"
signal_dir="${SIGNAL_DIR:-}"

while [ $# -gt 0 ]; do
	case "$1" in
		--link)
			link=1
			shift
			;;
		--libsignal)
			libsignal_dir="$2"
			shift 2
			;;
		--signal)
			signal_dir="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			if [ -z "$libsignal_dir" ]; then
				libsignal_dir="$1"
			elif [ -z "$signal_dir" ]; then
				signal_dir="$1"
			else
				echo "unexpected argument: $1" >&2
				usage
				exit 2
			fi
			shift
			;;
	esac
done

if [ -z "$libsignal_dir" ]; then
	echo "missing libsignal_dir" >&2
	usage
	exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
if [ -z "$signal_dir" ]; then
	signal_dir=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
fi

if [ ! -d "$libsignal_dir" ]; then
	echo "libsignal_dir not found: $libsignal_dir" >&2
	exit 2
fi
if [ ! -d "$signal_dir" ]; then
	echo "signal_repo_dir not found: $signal_dir" >&2
	exit 2
fi

libsignal_bin="$libsignal_dir/rust/protocol/src/bin"
libsignal_cargo="$libsignal_dir/rust/protocol/Cargo.toml"
signal_vectors="$signal_dir/testing/vectors"

if [ ! -d "$libsignal_bin" ]; then
	echo "libsignal bin dir not found: $libsignal_bin" >&2
	exit 2
fi
if [ ! -f "$libsignal_cargo" ]; then
	echo "libsignal Cargo.toml not found: $libsignal_cargo" >&2
	exit 2
fi
if [ ! -d "$signal_vectors" ]; then
	echo "signal vectors dir not found: $signal_vectors" >&2
	exit 2
fi

if ! grep -q "curve25519-dalek" "$libsignal_cargo"; then
	echo "missing curve25519-dalek in $libsignal_cargo" >&2
	echo "add it under [dependencies] before running this script" >&2
	exit 2
fi

plan_commit=$(awk -F'`' '/commit `/{print $2; exit}' "$signal_dir/PLAN.md" || true)
if [ -n "$plan_commit" ] && command -v git >/dev/null 2>&1; then
	actual_commit=$(git -C "$libsignal_dir" rev-parse HEAD 2>/dev/null || true)
	if [ -n "$actual_commit" ] && [ "$plan_commit" != "$actual_commit" ]; then
		echo "warning: libsignal HEAD $actual_commit does not match PLAN.md $plan_commit" >&2
	fi
fi

if [ "$link" -eq 1 ]; then
	ln -sf "$script_dir/gen_x3dh_vectors.rs" "$libsignal_bin/gen_x3dh_vectors.rs"
	ln -sf "$script_dir/gen_ratchet_vectors.rs" "$libsignal_bin/gen_ratchet_vectors.rs"
else
	cp "$script_dir/gen_x3dh_vectors.rs" "$libsignal_bin/gen_x3dh_vectors.rs"
	cp "$script_dir/gen_ratchet_vectors.rs" "$libsignal_bin/gen_ratchet_vectors.rs"
fi

(cd "$libsignal_dir/rust/protocol" && cargo run --quiet --bin gen_x3dh_vectors > "$signal_vectors/x3dh_libsignal.json")
(cd "$libsignal_dir/rust/protocol" && cargo run --quiet --bin gen_ratchet_vectors > "$signal_vectors/ratchet_libsignal.json")

echo "wrote: $signal_vectors/x3dh_libsignal.json"
echo "wrote: $signal_vectors/ratchet_libsignal.json"
