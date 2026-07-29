# Installing Umbra (portable archives)

`umbra-build --package` produces a self-contained archive with the binaries, the
SymCrypt runtime library, the signed integrity manifest (if you signed), and the
docs. There is no system installer — you run it in place from any folder.

## Windows (`umbra-<variant>-windows.zip`)

1. Unzip anywhere you can write (e.g. `C:\Umbra`).
2. Contents: `umbra.exe` (desktop app), `unichat.exe` (CLI), `symcrypt.dll`,
   and — if signed — `umbra.manifest`.
3. Run `umbra.exe`. (Optional: create a shortcut to it.)
4. **Lock it down** (recommended): from the repo, run
   ```powershell
   powershell -File scripts\harden.ps1 -InstallDir "C:\Umbra"
   ```
   which sets owner-only, read-only ACLs and reminds you how to Authenticode-sign.

## Linux (`umbra-<variant>-linux.tar.gz`)

1. Extract: `tar xzf umbra-<variant>-linux.tar.gz && cd umbra-<variant>-linux`
2. Contents: `umbra` (app), `unichat` (CLI), `libsymcrypt.so*`, `umbra.sh`
   launcher, and — if signed — `umbra.manifest`.
3. Run it. The binary is linked with `-rpath,$ORIGIN`, so `./umbra` finds the
   co-located `libsymcrypt.so`. If your loader ignores rpath, use the launcher:
   ```sh
   ./umbra.sh          # sets LD_LIBRARY_PATH then runs ./umbra
   ```
4. Runtime deps: ALSA (`libasound2`) for audio and a V4L2 camera for video.
   Optional desktop entry:
   ```sh
   cat > ~/.local/share/applications/umbra.desktop <<EOF
   [Desktop Entry]
   Type=Application
   Name=Umbra
   Exec=$(pwd)/umbra.sh
   Terminal=false
   Categories=Network;InstantMessaging;
   EOF
   ```

## The relay

The relay archive (`umbra-<variant>-relay-*`) contains `umbra-relay` + SymCrypt.
For a `--torify` relay it also ships `umbra-relay.toml` (private mode, loopback
binds) and `torrc.onion.sample`. See [USAGE.md](USAGE.md#running-the-relay).

## Tamper-evidence note

If the archive includes `umbra.manifest`, the binaries verify themselves against
it at startup and **refuse to run if altered**. Keep `umbra.manifest` beside the
binaries. If you rebuild, re-sign (see [BUILD.md](BUILD.md)) — a stale manifest
makes the app refuse to launch, and the GUI has no console to say why.
