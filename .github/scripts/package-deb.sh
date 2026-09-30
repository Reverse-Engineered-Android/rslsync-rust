#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <version> <deb-architecture> <binary> <output-directory>" >&2
    exit 2
fi

version="$1"
deb_arch="$2"
binary="$3"
output_dir="$4"

if [[ ! "$version" =~ ^[0-9][A-Za-z0-9.+:~-]*$ ]]; then
    echo "invalid Debian package version: $version" >&2
    exit 2
fi

case "$deb_arch" in
    amd64 | arm64 | riscv64 | loong64) ;;
    *)
        echo "unsupported Debian architecture: $deb_arch" >&2
        exit 2
        ;;
esac

if [[ ! -f "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="$(realpath "$binary")"
mkdir -p "$output_dir"
output_dir="$(realpath "$output_dir")"
package_root="$(mktemp -d)"
trap 'rm -rf "$package_root"' EXIT

install -Dm0755 "$binary" "$package_root/usr/bin/rustsync"
install -Dm0644 "$repo_root/README.md" "$package_root/usr/share/doc/rustsync/README.md"
install -Dm0644 "$repo_root/LICENSE" "$package_root/usr/share/doc/rustsync/copyright"

installed_size="$(du -sk "$package_root" | awk '{print $1}')"
mkdir -p "$package_root/DEBIAN"
cat > "$package_root/DEBIAN/control" <<EOF
Package: rustsync
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: Reverse-Engineered-Android maintainers <Reverse-Engineered-Android@users.noreply.github.com>
Installed-Size: $installed_size
Homepage: https://github.com/Reverse-Engineered-Android/rustsync
Description: Linux file synchronization CLI
 Portable rustsync executable with vendored cryptography and no external
 shared-library runtime dependencies.
EOF

output_path="$output_dir/rustsync_${version}_${deb_arch}.deb"
dpkg-deb --build --root-owner-group "$package_root" "$output_path"
dpkg-deb --info "$output_path"
dpkg-deb --contents "$output_path"
