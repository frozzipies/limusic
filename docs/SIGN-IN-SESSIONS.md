# Sign-in sessions: where the data lives

Everything below is per-OS under Tauri's app-data dir for identifier `com.limusic.desktop`
(`tauri.conf.json`), created in `lib.rs` via `app.path().app_data_dir()`:

| OS | Directory |
|---|---|
| Windows | `%APPDATA%\com.limusic.desktop\` |
| Linux | `~/.local/share/com.limusic.desktop/` |
| macOS | `~/Library/Application Support/com.limusic.desktop/` |

## 1. SQLite: `limusic.sqlite`

The canonical store of your saved Google accounts and the active session. Schema: `src-tauri/src/db.rs`.

### `accounts` table

One row per saved Google account.

| Column | Contents |
|---|---|
| `id` | Opaque account key: `ga-<md5>` over the cookie's long-lived `SAPISID` value (`db::account_key`). Stable across Rust releases, and the SAPISID itself is not recoverable from it. |
| `session_cookie` | The full `Cookie:` header captured at sign-in (SAPISID, SID, `__Secure-*`, ...): the actual login credential. |
| `data_sync_id` | Server-issued delegated identity of the selected YouTube channel within this Google account. |
| `selected_identity_json` | Canonical account model: name, handle, email, thumbnail, channelId, data_sync_id. `NULL` means the login authenticated but a multi-channel pick is still pending. |
| `account_json` | The JSON shape the UI consumes (`signedIn`, `name`, ...). |
| `visitor_data` | Login-bound visitorData for this account. |
| `added_at` | Unix seconds; the account menu lists oldest first (re-logins do not reorder). |

### `settings` rows: active-account projections

The active account is projected into these keys so the startup bootstrap in `lib.rs`,
`AppState::account_snapshot`, and the channel switcher work unchanged:

| Key | Contents |
|---|---|
| `active_account` | `id` of the active account; absent means signed out (guest). |
| `session_cookie` | Cookie of the active account only. |
| `selected_identity_json`, `data_sync_id`, `account_json` | Active account's identity, written together (`Db::set_auth_identity`). |
| `account_selection_pending` | `"true"` while a multi-channel login awaits a pick. |
| `visitor_data` | Active session's visitorData (anonymous bootstrap id until first login). |

Databases from before multi-account are migrated once on open (`Db::open`): the legacy
`session_cookie` row becomes an `accounts` row and `active_account` is set.

## 2. Webview cookie store: the login window's own Google session

The sign-in webview (`src-tauri/src/session.rs`) is persistent (non-incognito) on purpose. Its
cookies live in the OS webview profile data *next to* the app data dir, not in the SQLite file:

- **Windows (WebView2):** user-data folder under `%LOCALAPPDATA%\com.limusic.desktop\EBWebView\`
- **Linux (WebKitGTK):** `~/.local/share/com.limusic.desktop/` webkit data (or XDG cache)
- **macOS (WKWebView):** inside `~/Library/Application Support/com.limusic.desktop/` WebKit data

This is why a re-login is one click with no password/paste, and why deleting `limusic.sqlite`
alone does not sign the webview out of Google. Limusic never reads this store as state:
`session.rs` copies the youtube-domain cookies out of it into a `Cookie` header and stores that
copy in SQLite.

It holds **one** Google session at a time, and **Add account** replaces it: that flow deletes every
google.com/youtube.com cookie from the store first (webview-side only, the SQLite rows are
untouched) so the fresh sign-in lands on the account the user actually entered. Two consequences:
a later plain "Sign in with Google" returns to whichever account the store now holds (the one
just added), so use Add account when you want a different one, and the automatic session healing
below can only re-mint that same account.

On Linux and macOS the webview identifies itself as **Safari on a Mac** (`session.rs::LOGIN_UA`),
because Google refuses sign-ins from embedded browsers it doesn't recognise and WebKitGTK is the
same engine as Safari. Google's "new sign-in" email repeats that user agent, so a Linux sign-in
shows up as macOS / Safari (#382). The IP and location in the alert are still yours. Windows sends
WebView2's own Edge user agent (#152).

## 3. What never leaves Rust

Auth material (`session_cookie`, `selected_identity_json`, `data_sync_id`, `account_json`,
`visitor_data`, `account_selection_pending`, `active_account`) is excluded from the `get_settings`
whitelist (`commands.rs::UI_SETTINGS`), so the renderer cannot read or overwrite it. The UI only
ever sees display fields plus opaque selectors (`id`, `selectionKey`).

## 4. Importing a session from Chrome (`browsercookies.rs`, `browserauth.rs`)

"Sign in with Chrome" reuses the Google session Chrome is already holding, so nothing has to be
typed. It is not an OAuth handshake and could not be: Google will not release `SID`/`SAPISID` to a
loopback redirect, and no OAuth scope returns the private InnerTube cookies the rest of the app
authenticates with. The only way to reuse a browser login is to read its cookie store, which is
what `yt-dlp --cookies-from-browser` does.

The import produces a `Cookie:` header and hands it to `AppState::sign_in` — the same seam the
login webview feeds — so multi-account, the channel picker and cookie rotation all behave
identically afterwards. Nothing imported reaches the renderer: the header exists only inside
`browserauth::sign_in_from_browser` and the `sign_in` argument.

**macOS only.** The database is the same everywhere; only the key differs (Linux:
gnome-keyring/kwallet or the literal `peanuts` with *one* PBKDF2 iteration; Windows: DPAPI, which
Chrome 127+ wraps in app-bound encryption that is deliberately unreadable from another process).
Elsewhere `browsercookies::available()` is false and the UI hides the button.

How a value is read, all of which Chromium fixes in `os_crypt_mac.mm`:

1. The key is `PBKDF2-HMAC-SHA1(keychain password, "saltysalt", 1003)`, 16 bytes.
2. Each `encrypted_value` is `v10` + AES-128-CBC, IV = sixteen spaces.
3. Chrome 131 (`meta.version` 24) prepends `SHA256(host_key)` to the plaintext. That prefix is
   *verified*, not assumed — which is also what makes a wrong key fail cleanly rather than yield
   plausible garbage that would then be sent to Google as a login attempt.
4. Only unpartitioned rows count (`top_frame_site_key = ''`). CHIPS-partitioned third-party
   cookies share a name with the first-party one and vastly outnumber it — on a real profile, 344
   of 364 YouTube rows are partitioned and `VISITOR_INFO1_LIVE` has 85 partitioned rows and no
   first-party row at all. Without the filter one of those is picked arbitrarily.
5. The surviving rows go through the same youtube-domain-only, most-specific-domain-wins rule as
   `session.rs::youtube_cookie_header`, so both sign-in paths produce the same shape of header.

### The Keychain prompt, and why `/usr/bin/security`

The password is read by shelling out to `security find-generic-password`, not by linking
`security-framework`. The Keychain grants access per *calling binary*, identified by its
code-signing requirement; release builds are signed ad-hoc, whose identity is the cdhash and so
changes on every build. An in-process read would therefore re-prompt after every update and every
`cargo tauri dev` recompile, while `/usr/bin/security` is Apple-signed and stable.

**Chrome's ACL lists Chrome alone, so a foreign reader gets the full dialog and the user must type
their macOS login password.** Two answers, and the difference matters:

- **Allow** — valid for that one `security` call. The derived key is then cached in memory for the
  life of the process, so this is one prompt per launch, and typically only on the launch where
  the import actually happens.
- **Always Allow** — adds `/usr/bin/security` to the item's ACL permanently, which means **any
  process running as this user can read Chrome Safe Storage silently from then on**. That is a
  real and lasting reduction in the machine's security posture. The picker says so before the
  dialog appears (`nav.chrome_keychain_hint`), and Allow is what it recommends.

The key is never written to `settings`, to a file, or to the app's own Keychain: it is a
cross-application credential, and persisting it would turn a prompt-gated read into a standing
capability.

### Provenance and healing

`account_sources` (`id`, `source`) records which browser profile an account was imported from,
keyed on the same `ga-<md5>` id as `accounts`. It is a sidecar table rather than a column on
`accounts` so `StoredAccount` and every `INSERT` above it stay untouched. The row is written only
*after* `sign_in` succeeds, so a rejected cookie cannot teach the healer to return to a profile
that does not authenticate.

`refresh_session` consults it first: an imported account heals by re-importing from its browser,
because this webview may never have held a Google session at all. The re-import compares SAPISID
before applying anything, so healing can no more move the user to a different account than the
webview path can. A row left behind by a removed account is harmless for the same reason — the
compare simply fails and the webview heal takes over.

**Known limitation:** Chrome's on-disk jar only rotates while Chrome itself is running and
visiting Google. With Chrome closed, the re-import returns the jar we already have, the heal
declines, and it falls through to the webview — which for an imported account has nothing to
re-mint from. In practice this is rare, because the imported jar carries the long-lived
`__Secure-1PSID` and the transport's own `Set-Cookie` merge plus the half-hourly `account_menu`
ping keep the app's copy rolling without Chrome. When it does happen, opening YouTube in Chrome
once and retrying is the fix.

This is a best-effort convenience, not a supported Google flow. If Chrome adopts app-bound
encryption (`v20`) on macOS as it has on Windows, it stops working and says so rather than
failing obscurely; the login webview remains the path that always works.

## Flow summary

- **Sign in** (`login_webview`): ServiceLogin webview, redirect to music.youtube.com, cookies
  captured, validated via `account_menu`, `accounts` row upserted (keyed on SAPISID, so a new
  Google account adds a row and a known one refreshes its own), `active_account` set,
  `auth-changed` emitted.
- **Sign in with Chrome** (`sign_in_with_browser`): Chrome's cookie store is read and decrypted,
  the youtube-domain jar becomes a `Cookie` header, and it goes through the same `AppState::sign_in`
  as above. `account_sources` records the profile afterwards. See §4; macOS only.
- **Session freshness** (#165 / KI-2): Google rotates its short-lived tokens
  (`__Secure-*SIDTS`) on authenticated responses. The innertube transport merges every
  `Set-Cookie` into its jar and raises `cookie_changed`; the app writes the rotated jar back to
  the `session_cookie` projection *and* the account's own row, so a switch away and back, or a
  restart, never revives a dead cookie. A half-hourly `account_menu` ping keeps the jar rolling
  while the app is idle, since rotation only happens on requests the app actually makes. If
  YouTube rejects the session outright, `refresh_session` re-mints it from the login webview, but
  only when that webview still holds the same Google account, so healing can never move the app to
  a different account behind the user's back.
- **Add account** (`login_webview` with `add_account: true`): webview signed out of Google, then
  Google's `accounts.google.com/AddSession` screen. If the cookie store cannot be cleared the flow
  stops with a `login-error` rather than signing in as the account already there.
- **Switch account** (`switch_google_account`): stored cookie validated with `account_menu` first,
  then projections and `active_account` swap atomically, playlist index forgotten, `auth-changed`
  emitted. A row saved mid multi-channel sign-in reopens the required channel picker.
- **Sign out** (`sign_out`): drops to guest. The account stays in the saved list, one click from
  coming back.
- **Remove account** (`remove_google_account`): deletes the account's row, and drops to guest if it
  was the active one. Other saved accounts stay listed and switchable.
- **Channel switch** (`switch_account`): unchanged, picks a YouTube channel *within* the active
  Google account.
