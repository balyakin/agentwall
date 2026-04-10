#!/usr/bin/env sh
set -eu

REPO="${AGENTWALL_REPO:-balyakin/agentwall}"

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

api="https://api.github.com/repos/$REPO/releases/latest"
tag="$(curl -fsSL "$api" | awk -F '"' '/tag_name/ {print $4; exit}')"
if [ -z "$tag" ]; then
  echo "Failed to detect latest release tag" >&2
  exit 1
fi

version="${tag#v}"
ext="tar.gz"
binary_name="agentwall"
if [ "$os" = "windows" ]; then
  ext="zip"
  binary_name="agentwall.exe"
fi
archive="agentwall_${version}_${os}_${arch}.${ext}"
checksums="checksums.txt"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

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

target_dir="$HOME/.local/bin"
if [ -w "/usr/local/bin" ]; then
  target_dir="/usr/local/bin"
fi
mkdir -p "$target_dir"
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
