#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -z "${ANDROID_NDK_HOME:-}${ANDROID_NDK_ROOT:-}${ANDROID_NDK_LATEST_HOME:-}" ]]; then
    for candidate in "$HOME/Android/Sdk/ndk"/* "$ANDROID_HOME/ndk"/* "${ANDROID_SDK_ROOT:-/nonexistent}/ndk"/*; do
        if [[ -d "$candidate" ]]; then
            ANDROID_NDK_HOME="$candidate"
            break
        fi
    done
fi
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
if [[ -z "$NDK" || ! -d "$NDK" ]]; then
    echo "Android NDK not found; set ANDROID_NDK_HOME" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) host_tag="darwin-x86_64" ;;
    Linux) host_tag="linux-x86_64" ;;
    *) echo "unsupported build host: $(uname -s)" >&2; exit 1 ;;
esac
toolchain="$NDK/toolchains/llvm/prebuilt/$host_tag/bin"
api_level="${ANDROID_API_LEVEL:-21}"
export ANDROID_NDK_HOME="$NDK"
export ANDROID_NDK_ROOT="$NDK"
targets=(
    "aarch64-linux-android arm64-v8a aarch64-linux-android${api_level}-clang"
    "armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi${api_level}-clang"
    "i686-linux-android x86 i686-linux-android${api_level}-clang"
    "x86_64-linux-android x86_64 x86_64-linux-android${api_level}-clang"
)

for entry in "${targets[@]}"; do
    read -r rust_target abi clang_name <<< "$entry"
    echo "==> rustsync $rust_target -> $abi"
    rustup target add "$rust_target"
    target_env_lower="$(tr '[:upper:]-' '[:lower:]_' <<< "$rust_target")"
    target_env_upper="$(tr '[:lower:]-' '[:upper:]_' <<< "$rust_target")"
    export "CC_${target_env_lower}=$toolchain/$clang_name"
    export "AR_${target_env_lower}=$toolchain/llvm-ar"
    export "CARGO_TARGET_${target_env_upper}_LINKER=$toolchain/$clang_name"
    export OPENSSL_STATIC=1
        CARGO_TARGET_DIR="$repo_root/target/android" \
        cargo build --locked --release --target "$rust_target"
    source_binary="$repo_root/target/android/$rust_target/release/rustsync"
    destination="$repo_root/android/app/src/main/jniLibs/$abi/librustsync.so"
    install -Dm0755 "$source_binary" "$destination"
    echo "installed $destination"
done

echo "Android rustsync binaries installed under android/app/src/main/jniLibs/"
