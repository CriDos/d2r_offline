# d2r_offline 1.0

`d2r_offline` is a compact C++ project for reproducing the offline startup/session flow of Diablo II: Resurrected without the Blizzard launcher through a proxy `winhttp.dll`.

The project does the following:

- replaces `winhttp.dll` while forwarding the original WinHTTP exports to the real system library
- publishes the expected environment and registry responses
- patches the trusted `PUBLIC KEY` in the Diablo II: Resurrected process memory
- generates a compatible `%LocalAppData%\Blizzard Entertainment\ClientSdk\cookie.bin`

## Structure

- `src/config` — config loading and locale normalization
- `src/crypto` — Windows CNG/CryptoAPI backend and Serpent CTR
- `src/cookie` — claims, machine context, cryptobox, and `cookie.bin` writing
- `src/exports` — export list and asm forwarders
- `src/proxy` — process bootstrap and WinHTTP forwarder loading
- `src/runtime` — runtime patches and registry hook implementation
- `src/support` — shared types, key material, logging, and platform helpers

## Build

Requirements:

- Windows x64
- Visual Studio 2022 Build Tools

Build:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Output:

- `build\winhttp.dll`

## Usage

To use the proxy with Diablo II: Resurrected:

1. Either build the project and take `build\winhttp.dll`, or [download](https://github.com/CriDos/d2r_offline/releases) `winhttp.dll` from the project release.
2. Copy `winhttp.dll` into the game directory, next to the main game executable.
3. Start the game executable directly, without the Blizzard launcher.
4. On first launch, let the DLL generate `d2r_offline.ini` automatically or place your own config next to `winhttp.dll`.
5. After a successful start, the offline cookie will be written to `%LocalAppData%\Blizzard Entertainment\ClientSdk\cookie.bin`.

Recommended first-run checks:

- `d2r_offline.log` is created next to `winhttp.dll`
- `cookie.bin` is created under `%LocalAppData%\Blizzard Entertainment\ClientSdk\`
- the game starts with the expected language and offline session state

## Config

The DLL looks for `d2r_offline.ini` next to itself. If the file does not exist, it is created automatically:

```ini
[Settings]
Locale=english
LocaleAudio=english
Entitlements=hd,beta,rotw-dlc
```

Supported keys:

- `Locale`
- `LocaleAudio`
- `Entitlements`

Supported `Locale` and `LocaleAudio` values:

- `english` -> `enUS`
- `german` -> `deDE`
- `spanish` -> `esES`
- `latam` -> `esMX`
- `french` -> `frFR`
- `italian` -> `itIT`
- `koreana` / `korean` -> `koKR`
- `polish` -> `plPL`
- `brazilian` -> `ptBR`
- `portuguese` -> `ptPT`
- `russian` -> `ruRU`
- `tchinese` -> `zhTW`
- `schinese` -> `zhCN`
- `japanese` -> `jaJP`

You can also provide a Blizzard locale code directly, for example `enUS` or `ruRU`.

The runtime log is written to `d2r_offline.log` next to the DLL and is recreated on every launch.

## Notes

- the output file remains `winhttp.dll` because the client loads that exact module name
- the implementation targets practical compatibility, not binary identity
- the crypto layer uses Windows CNG/CryptoAPI and vendored Serpent
