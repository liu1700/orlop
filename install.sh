#!/bin/sh
# orlop installer. Downloads prebuilt binaries (orlop, orlop-control,
# orlop-server) for this OS/arch from a GitHub release and installs them into a
# bin directory on your PATH.
#
#   curl -fsSL https://orlop.dev/install.sh | sh
#   # or, straight from the repo:
#   curl -fsSL https://raw.githubusercontent.com/liu1700/orlop/main/install.sh | sh
#
# Environment overrides:
#   ORLOP_VERSION   release tag to install (default: latest), e.g. v1.0.0-rc.18
#   ORLOP_BIN_DIR   install directory (default: $HOME/.local/bin)
set -eu

REPO="liu1700/orlop"
BINARIES="orlop orlop-control orlop-server"

info() { printf 'orlop-install: %s\n' "$1" >&2; }
die() {
	printf 'orlop-install: error: %s\n' "$1" >&2
	exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

need uname
need tar
need mktemp

# Pick a downloader once: curl or wget.
if command -v curl >/dev/null 2>&1; then
	dl() { curl -fsSL "$1" -o "$2"; }
	dl_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	dl() { wget -qO "$2" "$1"; }
	dl_stdout() { wget -qO- "$1"; }
else
	die "need curl or wget to download"
fi

# Detect OS.
os="$(uname -s)"
case "$os" in
Linux) os="linux" ;;
Darwin) os="darwin" ;;
*) die "unsupported OS: $os (linux and darwin only)" ;;
esac

# Detect architecture.
arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*) die "unsupported architecture: $arch (amd64 and arm64 only)" ;;
esac

# Resolve the release tag.
tag="${ORLOP_VERSION:-}"
if [ -z "$tag" ]; then
	info "resolving the latest release"
	tag="$(dl_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -n1 | cut -d'"' -f4)"
	[ -n "$tag" ] || die "could not determine the latest release; set ORLOP_VERSION=vX.Y.Z"
fi
version="${tag#v}"

bindir="${ORLOP_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$bindir" || die "cannot create install dir: $bindir"

asset="orlop_${version}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading ${asset} (${tag})"
dl "$url" "$tmp/$asset" || die "download failed: $url"

# Verify the checksum when the sidecar file is published alongside the tarball.
if dl "${url}.sha256" "$tmp/$asset.sha256" 2>/dev/null; then
	if command -v shasum >/dev/null 2>&1; then
		(cd "$tmp" && shasum -a 256 -c "$asset.sha256" >/dev/null 2>&1) ||
			die "checksum verification failed"
		info "checksum ok"
	elif command -v sha256sum >/dev/null 2>&1; then
		(cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null 2>&1) ||
			die "checksum verification failed"
		info "checksum ok"
	fi
fi

tar -C "$tmp" -xzf "$tmp/$asset" || die "extract failed"

for b in $BINARIES; do
	[ -f "$tmp/$b" ] || die "archive is missing expected binary: $b"
	cp "$tmp/$b" "$bindir/$b" || die "failed to install $b into $bindir"
	chmod 0755 "$bindir/$b"
done

info "installed [$BINARIES] into $bindir"

# Tell the user if the install dir is not already on PATH.
case ":$PATH:" in
*":$bindir:"*) : ;;
*)
	info "note: $bindir is not on your PATH; add it, e.g.:"
	printf '  export PATH="%s:$PATH"\n' "$bindir" >&2
	;;
esac

info "next: run 'orlop doctor' to confirm this host can mount"
