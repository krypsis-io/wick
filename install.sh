#!/bin/sh
# Wick installer — https://github.com/krypsis-io/wick
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/krypsis-io/wick/main/install.sh | sh
#
# Options (environment variables):
#   WICK_VERSION      Version to install without the leading v (default: latest)
#   WICK_INSTALL_DIR  Install directory (default: /usr/local/bin if writable,
#                     otherwise ~/.local/bin)
set -eu

REPO="krypsis-io/wick"

log() { printf 'wick-install: %s\n' "$1" >&2; }
fail() { log "ERROR: $1"; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux) echo linux ;;
        Darwin) echo darwin ;;
        MINGW* | MSYS* | CYGWIN*)
            fail "Windows detected: download a zip from https://github.com/${REPO}/releases instead"
            ;;
        *) fail "unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo amd64 ;;
        arm64 | aarch64) echo arm64 ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac
}

# Resolve the latest release tag by following the GitHub releases/latest
# redirect. Avoids the API (and its rate limits) and needs no JSON parsing.
latest_version() {
    url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") ||
        fail "could not resolve the latest release"
    version="${url##*/tag/v}"
    [ "$version" != "$url" ] || fail "unexpected release URL: $url"
    echo "$version"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        fail "need sha256sum or shasum to verify the download"
    fi
}

resolve_install_dir() {
    if [ -n "${WICK_INSTALL_DIR:-}" ]; then
        echo "$WICK_INSTALL_DIR"
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        echo /usr/local/bin
    else
        echo "${HOME}/.local/bin"
    fi
}

main() {
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    command -v tar >/dev/null 2>&1 || fail "tar is required"

    os=$(detect_os)
    arch=$(detect_arch)
    version="${WICK_VERSION:-$(latest_version)}"

    archive="wick_${version}_${os}_${arch}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/v${version}"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT INT TERM

    log "downloading wick v${version} (${os}/${arch})"
    curl -fsSL -o "${tmpdir}/${archive}" "${base_url}/${archive}" ||
        fail "download failed: ${base_url}/${archive}"
    curl -fsSL -o "${tmpdir}/checksums.txt" "${base_url}/checksums.txt" ||
        fail "could not download checksums.txt for verification"

    expected=$(awk -v f="$archive" '$2 == f {print $1}' "${tmpdir}/checksums.txt")
    [ -n "$expected" ] || fail "no checksum for ${archive} in checksums.txt"
    actual=$(sha256_of "${tmpdir}/${archive}")
    [ "$actual" = "$expected" ] || fail "checksum mismatch for ${archive}: expected ${expected}, got ${actual}"
    log "checksum verified"

    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir" wick

    install_dir=$(resolve_install_dir)
    mkdir -p "$install_dir" || fail "cannot create ${install_dir}"
    [ -w "$install_dir" ] || fail "cannot write to ${install_dir} — rerun with WICK_INSTALL_DIR set to a writable directory, or with sudo"

    install -m 0755 "${tmpdir}/wick" "${install_dir}/wick"
    log "installed $("${install_dir}/wick" version) to ${install_dir}/wick"

    case ":${PATH}:" in
        *":${install_dir}:"*) ;;
        *) log "NOTE: ${install_dir} is not on your PATH — add it to your shell profile" ;;
    esac
}

main
