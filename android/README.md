# RustSync Android

`android/` is a Java Android client for the bundled `rustsync` executable. The
app launches `librustsync.so` from `ApplicationInfo.nativeLibraryDir` and talks
to its loopback REST API. Long-running `serve`, `serve-upstream`,
`connect-upstream`, and `tracker-serve` commands are managed directly as child
processes with live log files.

The client supports these folder locations:

* app-private `filesDir` and cache directories;
* external app-specific and external cache directories;
* native absolute paths (useful with root, Termux, or mounted filesystems);
* Android Storage Access Framework document trees. SAF is bridged into an
  app-private mirror so the Rust filesystem code can run unchanged. The bridge
  merges newer files in both directions, preserves conflicting local files as
  `.rustsync-conflict-*`, and intentionally does not propagate deletions.

The SAF bridge is synchronized before a folder scan and on demand from the
main screen. Long-running synchronization runs against the mirror; use the
bridge button or return to the app to publish local changes back to the
provider. Providers that cannot provide stable document IDs or write access
need to be used through a native mount path instead.

## Build

Install an Android SDK/NDK and Rust Android targets, then run:

```bash
./scripts/build-android-native.sh
cd android
./gradlew :app:assembleDebug :app:assembleRelease
```

The CI workflow uploads both APKs for every push and pull request. To sign the
release with a stable production key, create `android/keystore.properties`:

```properties
storeFile=/absolute/path/to/release.keystore
storePassword=...
keyAlias=...
keyPassword=...
```

When those properties are absent, `assembleRelease` uses the debug key so the
published artifact remains installable; the APK name and repository history
make this fallback visible.
