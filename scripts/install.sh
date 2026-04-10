#!/usr/bin/env sh
set -eu

REPO="${AGENTWALL_REPO:-balyakin/agentwall}"
REF="${AGENTWALL_REF:-main}"
MODULE="${AGENTWALL_MODULE:-github.com/balyakin/agentwall}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

case "$os" in
  linux|darwin) ;;
  msys*|mingw*|cygwin*) os="windows" ;;
  *)
    echo "Unsupported OS: $os" >&2
    exit 1
    ;;
esac

ext="tar.gz"
binary_name="agentwall"
if [ "$os" = "windows" ]; then
  ext="zip"
  binary_name="agentwall.exe"
fi

target_dir="$HOME/.local/bin"
if [ -w "/usr/local/bin" ]; then
  target_dir="/usr/local/bin"
fi
mkdir -p "$target_dir"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

install_from_source() {
  if ! command -v go >/dev/null 2>&1; then
    echo "No GitHub release found for $REPO and Go is not installed." >&2
    echo "Install Go, then rerun this installer or download a release binary." >&2
    exit 1
  fi
  echo "No GitHub release found for $REPO. Building $REF from source with Go..." >&2
  curl -fsSL "https://github.com/$REPO/archive/$REF.tar.gz" -o "$tmpdir/source.tar.gz"
  tar -xzf "$tmpdir/source.tar.gz" -C "$tmpdir"
  srcdir="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [ -z "$srcdir" ]; then
    echo "Failed to unpack source archive" >&2
    exit 1
  fi
  build_date="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  ldflags="-s -w"
  ldflags="$ldflags -X $MODULE/internal/version.Version=dev-$REF"
  ldflags="$ldflags -X $MODULE/internal/version.Commit=$REF"
  ldflags="$ldflags -X $MODULE/internal/version.BuildDate=$build_date"
  (
    cd "$srcdir"
    go build -trimpath \
      -ldflags "$ldflags" \
      -o "$target_dir/$binary_name" \
      ./cmd/agentwall
  )
}

tag="${AGENTWALL_VERSION:-}"
if [ -z "$tag" ]; then
  api="https://api.github.com/repos/$REPO/releases/latest"
  tag="$(curl -fsSL "$api" 2>/dev/null | awk -F '"' '/tag_name/ {print $4; exit}')"
fi

if [ -z "$tag" ]; then
  install_from_source
  echo "Installed: $target_dir/$binary_name"
  "$target_dir/$binary_name" doctor || true
  echo "Try: agentwall run -- claude"
  exit 0
fi

version="${tag#v}"
archive="agentwall_${version}_${os}_${arch}.${ext}"
checksums="checksums.txt"

base="https://github.com/$REPO/releases/download/$tag"
curl -fsSL "$base/$archive" -o "$tmpdir/$archive"
curl -fsSL "$base/$checksums" -o "$tmpdir/$checksums"

expected="$(grep "  $archive$" "$tmpdir/$checksums" | awk '{print $1}')"
if [ -z "$expected" ]; then
  echo "Failed to find checksum for $archive" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmpdir/$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmpdir/$archive" | awk '{print $1}')"
else
  echo "No SHA256 tool found (sha256sum/shasum)" >&2
  exit 1
fi

if [ "$expected" != "$actual" ]; then
  echo "Checksum verification failed" >&2
  exit 1
fi

if [ "$ext" = "tar.gz" ]; then
  tar -xzf "$tmpdir/$archive" -C "$tmpdir"
else
  unzip -q "$tmpdir/$archive" -d "$tmpdir"
fi

install "$tmpdir/$binary_name" "$target_dir/$binary_name"

echo "Installed: $target_dir/$binary_name"

if [ "$os" != "windows" ]; then
  printf "Install CA into system trust store now? [y/N] "
  read -r answer || true
  case "$answer" in
    y|Y|yes|YES)
      "$target_dir/$binary_name" ca install || true
      ;;
  esac
fi

"$target_dir/$binary_name" doctor || true
echo "Try: agentwall run -- claude"
