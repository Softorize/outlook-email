# outlook-email

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange.svg)](https://ziglang.org/)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue.svg)](#2-building-for-distribution)

A command-line client for Microsoft 365 mail, written in Zig 0.15.2.
The project is `outlook-email`; the binary it produces is `ocli`.

Designed for enterprise distribution: the IT team builds the binary once with
the company's Azure client ID baked in, signs it, and ships it to end users.
End users download the binary, run `ocli login`, authenticate by typing a
short code into a browser, and start reading, searching, and sending mail from
the terminal.

- Multi-tenant Azure AD + personal Microsoft accounts
- OAuth 2.0 device code flow -- no browser redirect, no local HTTP server
- Refresh tokens stored in the OS credential store (macOS Keychain, Windows
  Credential Manager, Linux libsecret with an encrypted-file fallback)
- Silent token refresh, multiple saved accounts, `ocli use` to switch
- Subcommand-style CLI (`list`, `read`, `send`, `reply`, `forward`, `delete`,
  `archive`, `search`, `folders`) with both coloured human output and `--json`
- Honours `HTTPS_PROXY` / `HTTP_PROXY` for corporate networks, plus
  `--ca-bundle` for TLS-intercepting proxies
- Graph 429 / Retry-After backoff and human-friendly error messages
- Attachments: upload (small inline + large `createUploadSession` chunked),
  download via `--save-attachments`

> **Status**: production-ready v1. Fullscreen TUI, bracketed paste in compose,
> and $EDITOR integration are explicit non-goals for this release.

---

## Contents

1. [Azure app registration](#1-azure-app-registration)
2. [Building for distribution](#2-building-for-distribution)
3. [Signing and packaging](#3-signing-and-packaging)
4. [End-user first run](#4-end-user-first-run)
5. [Configuration](#5-configuration)
6. [Commands](#6-commands)
7. [Troubleshooting](#7-troubleshooting)
8. [Security notes](#8-security-notes)
9. [Repository layout](#9-repository-layout)
10. [Running tests](#10-running-tests)
11. [License](#11-license)

---

## 1. Azure app registration

These steps are performed **once** by the IT or platform team. End users
never have to touch Azure.

1. Sign in to <https://portal.azure.com> as a user who can register apps in
   your tenant (Application Administrator or higher).
2. Go to **Microsoft Entra ID** → **App registrations** → **New registration**.
3. Fill in the form:
   - **Name**: `outlook-email` (or whatever you like)
   - **Supported account types**: select
     **Accounts in any organizational directory (Any Microsoft Entra ID
     tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)**.
     This is required for the `common` tenant + personal accounts to work.
   - **Redirect URI**: leave blank. The device code flow does not use one.
4. Click **Register**. Copy the **Application (client) ID** from the overview
   page. This GUID is what you bake into the binary in step 2.
5. Go to **Authentication**:
   - Under **Advanced settings** → **Allow public client flows**, toggle
     **Yes**. The device code flow is a public client flow and won't run
     without this.
   - Save.
6. Go to **API permissions** → **Add a permission** → **Microsoft Graph** →
   **Delegated permissions**. Add:
   - `offline_access`      (enables refresh tokens)
   - `User.Read`           (profile + UPN lookup)
   - `Mail.ReadWrite`      (read/update/delete messages and folders)
   - `Mail.Send`           (send messages)
   - `MailboxSettings.Read` (read mailbox settings for folder resolution)
7. Click **Grant admin consent for <your tenant>**. For multi-tenant use,
   admins in each *other* tenant that signs in will also need to grant
   consent once for their organisation; direct them to:
   ```
   https://login.microsoftonline.com/<their-tenant-id>/adminconsent?client_id=<your-client-id>
   ```
   Individual users can self-consent if the tenant admin has not blocked
   user consent.

That's it. The client ID you copied in step 4 is the only secret (and it
isn't really a secret for a public client) that has to travel with the binary.

---

## 2. Building for distribution

You need Zig 0.15.2 or newer. Install it from <https://ziglang.org/download/>.

```bash
git clone <this repo>
cd outlook-email

# Native build for testing.
zig build -Dclient-id=<YOUR-CLIENT-ID>

# Release builds. Pass the same -Dclient-id to every one.
zig build -Dclient-id=<GUID> -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl
zig build -Dclient-id=<GUID> -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl
zig build -Dclient-id=<GUID> -Doptimize=ReleaseSafe -Dtarget=x86_64-windows-gnu

# macOS builds must be run on a Mac because Security.framework stubs are
# needed for the Keychain backend.
zig build -Dclient-id=<GUID> -Doptimize=ReleaseSafe -Dtarget=aarch64-macos
zig build -Dclient-id=<GUID> -Doptimize=ReleaseSafe -Dtarget=x86_64-macos
```

Each invocation produces `zig-out/bin/ocli` (or `ocli.exe` on Windows).

### Build options

| Option | Default | Purpose |
|---|---|---|
| `-Dclient-id=<GUID>` | empty | Azure client ID baked into the binary. Required for anything except `--help` / `--version`. |
| `-Dtenant=<ID or "common">` | `common` | Default tenant. Leave as `common` for multi-tenant + MSA. |
| `-Dapp-version=<str>` | `0.1.0` | What `ocli --version` prints. |
| `-Dtarget=...` | native | Cross-compilation target triple. |
| `-Doptimize=ReleaseSafe` | `Debug` | Use `ReleaseSafe` for production. |
| `-Dstrip=true` | false | Strip debug info for smaller binaries. |

### Linux: static vs glibc builds

Linux ships with two reasonable variants:

- **`x86_64-linux-musl`** / **`aarch64-linux-musl`**: fully static. Runs on
  any kernel 2.6+. libsecret is loaded at runtime via `dlopen`, so the
  binary still works on headless boxes without libsecret -- it transparently
  falls back to the encrypted-file keystore with a warning.
- **`x86_64-linux-gnu`**: glibc build for desktops where libsecret is
  definitely present. Smaller surface to document, same code path.

Most deployments should ship the **musl** builds only.

---

## 3. Signing and packaging

- **macOS**: code-sign with your Developer ID certificate and notarise with
  `notarytool`. Without notarisation macOS Gatekeeper blocks first run with
  a cryptic "can't be opened" dialog.
  ```
  codesign --timestamp --options runtime -s "Developer ID Application: Acme Inc." ocli
  zip -r ocli.zip ocli
  xcrun notarytool submit ocli.zip --apple-id ... --team-id ... --wait
  xcrun stapler staple ocli
  ```
- **Windows**: sign with an EV code-signing certificate to avoid SmartScreen
  warnings.
  ```
  signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a ocli.exe
  ```
- **Linux**: no signing required; ship the musl binary as-is. If you publish
  via an internal apt/rpm repo, wrap it in a tiny package with a symlink
  from `/usr/local/bin/ocli` to the binary.

---

## 4. End-user first run

```
$ ocli login
To sign in, open https://microsoft.com/devicelogin in a browser and
enter the code:

    F7KG9-H2JW

Waiting for you to finish signing in...
Signed in as alice@contoso.com

$ ocli list
* @ 09:12 Bob Jones                    Weekly status
           Quick update on the migration and the staging deploys.
           id: AAMkAD0a...

    15:00 Newsletters                  (no subject)
           id: AAMkAD0b...
```

`ocli accounts` shows every account saved on this machine; `ocli use
bob@other.com` switches the active account. A single end user can legitimately
have their work Microsoft 365 account and a personal account signed in at
the same time and switch between them without logging out.

---

## 5. Configuration

The CLI reads settings from these sources in order of precedence (highest
first):

1. Command-line flags (`--json`, `--proxy`, `--client-id`, ...)
2. Environment variables (`HTTPS_PROXY`, `NO_COLOR`, `OCLI_CA_BUNDLE`,
   `OCLI_CLIENT_ID`, `OCLI_TENANT`)
3. User config file: `config.ini` under the OS config dir
4. Build-time constants baked in by IT (`-Dclient-id=...`)
5. Hardcoded defaults

User config dirs:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/outlook-email/config.ini` |
| Linux | `$XDG_CONFIG_HOME/outlook-email/config.ini` (fallback: `~/.config/outlook-email/config.ini`) |
| Windows | `%APPDATA%\outlook-email\config.ini` |

Example `config.ini`:

```ini
[account]
current = alice@contoso.com

[ui]
color = auto    ; auto, always, never

[network]
proxy = http://proxy.corp.example:8080
ca_bundle = /etc/pki/ca-trust/source/anchors/corp-root.pem
```

---

## 6. Commands

```
ocli login                      Sign in via device code flow
ocli logout [account]           Remove a saved session
ocli accounts                   List saved accounts
ocli use <account>              Switch the active account

ocli list [--folder X] [--top N] [--unread]
                                   List messages in a folder (default: inbox)
ocli read <id> [--save-attachments DIR]
                                   Show a full message (+ download attachments)
ocli search <query> [--top N]   Search messages by keyword
ocli folders                    List mail folders

ocli send --to "a,b" [--cc ...] [--bcc ...] --subject S [--attach file]...
ocli reply <id> [--all]         Reply (body from stdin)
ocli forward <id> --to "a,b"    Forward (body from stdin)
ocli delete <id>                Delete a message
ocli archive <id>               Move a message to the Archive folder

Global flags:
  --json             Machine-readable output (also suppresses colour)
  --no-color         Disable ANSI colours
  --verbose          Log HTTP activity to stderr
  --proxy URL        HTTPS proxy (overrides HTTPS_PROXY)
  --ca-bundle PATH   PEM file of root CAs for corporate TLS proxies
  --account EMAIL    Use this account just for this command
  --client-id ID     Override the built-in Azure client ID
  --tenant T         Override the Azure tenant (default: common)
```

### Composing messages

`send`, `reply`, and `forward` read the body from standard input. Type the
message and then:

- press **Ctrl-D** (Unix) or **Ctrl-Z then Enter** (Windows) to send on EOF, or
- type a single `.` on its own line.

Any header field (`--to`, `--subject`, `--cc`, ...) that you don't pass on
the command line is prompted for interactively.

### Attachments

```bash
ocli send --to boss@contoso.com --subject "Monthly report" \
  --attach ~/reports/april.pdf --attach ~/data/raw.csv
```

Small files (< 3 MB) are uploaded inline with the message. Large files go
through `createUploadSession` chunked upload. There is no hard size limit
beyond what Microsoft Graph enforces (about 150 MB per attachment).

To download attachments while reading a message:

```bash
ocli read AAMkAD0a --save-attachments ~/Downloads/report
```

### Scripting

All commands respect `--json` and print structured output to stdout while
keeping prompts and status on stderr:

```bash
# Get the unread count.
ocli list --unread --json | jq 'length'

# Subject line of the most recent message.
ocli list --json --top 1 | jq -r '.[0].subject'
```

---

## 7. Troubleshooting

### "Couldn't verify server certificate"

Your corporate proxy is re-signing TLS with a private root. Either make sure
that root is installed in the OS trust store (where Zig's TLS will pick it
up), or point to a PEM bundle explicitly:

```bash
ocli --ca-bundle /etc/pki/ca-trust/source/anchors/corp-root.pem list
# or, persistently:
export OCLI_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/corp-root.pem
```

### "The HTTPS proxy requires authentication"

Include credentials in the proxy URL:

```bash
export HTTPS_PROXY="http://user:s3cret@proxy.corp.example:8080"
```

NTLM/Kerberos-authenticating proxies are not supported. Use an alternate
proxy endpoint or a local bridge.

### "No credential store available"

libsecret couldn't be loaded (or isn't installed) on Linux. The CLI has
switched to the encrypted-file keystore at
`$XDG_DATA_HOME/outlook-email/credentials.enc`. This file is AES-256-GCM
encrypted with a key derived from `/etc/machine-id`. It's less secure than
a real keystore but usable on headless boxes. See [Security notes](#8-security-notes).

### "Sign-in expired. Run 'ocli login' again."

The refresh token was revoked or aged out. Run `ocli login` to get a
fresh one. If this happens repeatedly, ensure your tenant's conditional
access policies allow the device code flow for your user.

### `ocli login` loops forever

The device code expired before you entered it. Re-run `ocli login` and
enter the code faster. Default expiry is 15 minutes.

### All commands fail with "This build has no Azure client ID"

The binary was built without `-Dclient-id=...`. Rebuild with the value from
[step 1.4](#1-azure-app-registration), or pass `--client-id <GUID>` to override
at runtime.

---

## 8. Security notes

- Access and refresh tokens are stored in the **OS credential store** on
  macOS and Windows. They are scoped to the individual user account and
  are protected by the user's login session.
- On Linux with a desktop session, tokens go to the **Secret Service**
  (GNOME Keyring / KWallet) via libsecret. Same story: encrypted at rest,
  scoped to the user session, unlocked at login.
- On Linux **without** a Secret Service (headless boxes, containers,
  SSH-only users), the CLI falls back to an AES-256-GCM encrypted file at
  `$XDG_DATA_HOME/outlook-email/credentials.enc`. The key is derived from
  `/etc/machine-id`. This protects against a plain copy of the file but
  **not** against an attacker with local access to the same machine. If
  that's your threat model, install libsecret or don't use this tool on
  that host.
- The Azure client ID baked into the binary is **not** a secret. Public
  client flows are designed to work without one. Treat it like an
  identifier, not a credential.
- TLS verification uses the OS trust store by default. Corporate
  certificate interception works transparently as long as the proxy's
  root CA is installed in the OS store; otherwise pass `--ca-bundle`.
- No data is written anywhere other than the keystore and the user config
  file. No telemetry, no crash reports, no automatic updates.

---

## 9. Repository layout

```
src/
  main.zig                # process entry point
  errors.zig              # error set + Diagnostic
  config/                 # paths, ini, merged runtime config
  util/                   # time, base64url, mime, http_util, log
  keystore/               # macOS Keychain, Linux libsecret, Windows wincred, file fallback
  auth/                   # device flow, token type, session lifecycle
  graph/                  # Graph API types, HTTP wrapper, attachments
  render/                 # colour gating, human output, JSON output
  cli/                    # arg parsing, dispatch, subcommand implementations
    commands/             # one file per subcommand
tests/
  fixtures/               # captured Graph JSON for parser tests
build.zig
build.zig.zon
```

Every module has a single responsibility and a small public surface. The
single load-bearing boundary is `graph/http.zig`, which wraps
`std.http.Client` -- any future churn in Zig's HTTP or I/O APIs should be
contained to that one file.

---

## 10. Running tests

```bash
zig build test
# with verbose output:
zig build test --summary all
```

Unit tests are hermetic: they parse captured Graph JSON fixtures, exercise
the device code state machine with canned responses, verify the INI parser
and config-precedence logic, and round-trip the in-memory keystore backend.
Nothing hits the network. Native-keystore backends (Keychain / Credential
Manager / libsecret) are verified manually against real OS stores --
that's the one place a per-platform smoke test is required before each
release.

---

## 11. License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Softorize.
