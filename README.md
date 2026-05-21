# Secret Vault Desktop

Tauri desktop app for managing every `ddev-secret-vault` vault from one place.

## What It Does

- Reads the existing vaults from `~/.ddev/secret-vault/*.vault`
- Uses the same `openssl aes-256-cbc -pbkdf2 -iter 100000` format as the DDEV plugin
- Reuses the same shared master password and OS keychain entry (`ddev-secret-vault` / `master`)
- Creates vaults, edits secrets, copies `.env` exports, injects into a DDEV project's `.ddev/.env`, cleans the injected block, and rotates the shared password across all vaults
- Imports secrets from `.env` and `settings.local.php`
- Previews and optionally cleans imported source files while creating a `.bak` backup
- Supports opening the desktop app from `ddev vault ui --desktop`

## Run It

```bash
cd desktop
npm install
npm run tauri dev
```

## Build An App Bundle

```bash
cd desktop
npm run tauri build
```

## Notes

- The app expects your vaults to already live in `~/.ddev/secret-vault/`
- Injection and cleanup target the same marker block used by the DDEV plugin:

```bash
# --- secret-vault: BEGIN ---
...
# --- secret-vault: END ---
```
