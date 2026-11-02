//! Sign in with the Google session Chrome already holds, instead of typing credentials into the
//! login webview (`session.rs`).
//!
//! There is no handshake that does this properly: Google will not release `SID`/`SAPISID` to a
//! loopback redirect, and no OAuth scope returns the *private* InnerTube session cookies the rest
//! of the app authenticates with — OAuth would hand back a Bearer token for a different API. So
//! the only way to reuse a browser's login is to read its cookie store, the way
//! `yt-dlp --cookies-from-browser` does.
//!
//! The output is a `Cookie:` header that goes straight into [`crate::state::AppState::sign_in`],
//! the same seam the login webview feeds. Everything downstream — multi-account, the channel
//! picker, cookie rotation — is untouched.
//!
//! **macOS only for now.** The cookie *database* is identical on every platform; only the key
//! differs (Linux: gnome-keyring/kwallet, or the literal password `peanuts` with **1** PBKDF2
//! iteration rather than 1003; Windows: DPAPI, which Chrome 127+ wraps in app-bound encryption
//! that is deliberately unreadable from another process). Those belong beside [`imp`] behind
//! their own `#[cfg]`. Until then [`available`] reports false there and the UI hides the button.
//!
//! [`crypto`] is deliberately *not* `#[cfg]`-gated: only key acquisition and the data directory
//! are. CI runs on Linux, so gating the cipher would mean its tests never execute anywhere.

/// One Chrome profile directory that holds a cookie store.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChromeProfile {
    /// Directory name under the Chrome user-data dir (`Default`, `Profile 2`, ...). This is the
    /// opaque selector the UI hands back; the absolute path never leaves Rust.
    pub dir: String,
    /// What Chrome itself calls this profile, for the picker. Falls back to `dir`.
    pub name: String,
    /// Chrome's own account label for the profile, when it has one.
    pub email: Option<String>,
    /// There is an unpartitioned YouTube `SAPISID` row. Answering this decrypts nothing, so
    /// listing profiles never touches the Keychain.
    pub signed_in: bool,
}

pub use imp::{available, profiles, youtube_cookie_header};

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::ChromeProfile;

    const UNSUPPORTED: &str = "Signing in from Chrome is only supported on macOS in this build.";

    pub fn available() -> bool {
        false
    }

    pub fn profiles() -> Result<Vec<ChromeProfile>, String> {
        Err(UNSUPPORTED.into())
    }

    pub fn youtube_cookie_header(_profile_dir: &str) -> Result<String, String> {
        Err(UNSUPPORTED.into())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use super::crypto::{assemble, decrypt, derive_key, is_cookie_octet_safe};
    use super::ChromeProfile;

    fn user_data_dir() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join("Library/Application Support/Google/Chrome"))
    }

    pub fn available() -> bool {
        user_data_dir().is_some_and(|d| d.is_dir())
    }

    /// The Keychain password Chromium derives its key from, cached for the life of the process.
    ///
    /// Shelling out to `security` rather than linking `security-framework`: the Keychain grants
    /// access per *calling binary*, identified by its code-signing requirement. Release builds are
    /// signed ad-hoc (`codesign --sign -`), whose identity is the cdhash and therefore changes on
    /// every build — an in-process read would re-prompt after every update and after every
    /// `cargo tauri dev` recompile. `/usr/bin/security` is Apple-signed and stable, so one grant
    /// keeps working.
    ///
    /// The derived key is held in memory only, never written to `settings` or to disk: it is a
    /// cross-application credential, and persisting it would turn a prompt-gated read into a
    /// standing capability for anything that can read our files.
    fn chrome_key() -> Result<[u8; 16], String> {
        static CACHE: std::sync::Mutex<Option<[u8; 16]>> = std::sync::Mutex::new(None);
        if let Some(key) = *CACHE.lock().unwrap() {
            return Ok(key);
        }

        let out = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"])
            .output()
            .map_err(|e| format!("Could not read the macOS Keychain: {e}"))?;
        if !out.status.success() {
            // 44 is "no such item"; 128 is the user dismissing the prompt.
            return Err(match out.status.code() {
                Some(44) => "Chrome has no saved encryption key on this Mac — open Chrome once, \
                             then try again."
                    .to_string(),
                _ => "macOS did not grant access to Chrome's saved key. Choose Allow when \
                      prompted, then try again."
                    .to_string(),
            });
        }
        let password = String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string();
        if password.is_empty() {
            return Err("Chrome's Keychain entry is empty — is Chrome set up on this Mac?".into());
        }

        let key = derive_key(password.as_bytes());
        *CACHE.lock().unwrap() = Some(key);
        Ok(key)
    }

    /// Every profile directory that has a cookie store, with Chrome's own display names.
    pub fn profiles() -> Result<Vec<ChromeProfile>, String> {
        let root = user_data_dir().ok_or("Could not locate the Chrome data directory.")?;
        if !root.is_dir() {
            return Err("Chrome does not appear to be installed.".into());
        }

        // `Local State` maps directory name -> display name. Losing it costs the pretty names,
        // not the feature, so a parse failure degrades to directory names.
        let state: serde_json::Value = std::fs::read_to_string(root.join("Local State"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Null);

        let mut out = Vec::new();
        for entry in std::fs::read_dir(&root).map_err(|e| format!("Chrome data dir: {e}"))? {
            let Ok(entry) = entry else { continue };
            let cookies = entry.path().join("Cookies");
            if !cookies.is_file() {
                continue;
            }
            let dir = entry.file_name().to_string_lossy().into_owned();
            let meta = state.pointer(&format!("/profile/info_cache/{dir}"));
            // An ephemeral (guest) profile is not something to offer as a sign-in.
            if meta.and_then(|m| m.get("is_ephemeral")?.as_bool()).unwrap_or(false) {
                continue;
            }
            let field = |k: &str| {
                meta.and_then(|m| m.get(k)?.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
            };
            out.push(ChromeProfile {
                name: field("name")
                    .or_else(|| field("gaia_name"))
                    .unwrap_or_else(|| dir.clone()),
                email: field("user_name"),
                signed_in: has_youtube_session(&cookies),
                dir,
            });
        }
        out.sort_by(|a, b| a.dir.cmp(&b.dir));

        if out.is_empty() {
            return Err("No Chrome profiles with a cookie store were found.".into());
        }
        Ok(out)
    }

    /// Does this store hold a first-party YouTube login? Metadata only — nothing is decrypted, so
    /// building the picker never prompts for the Keychain. A store that will not open is reported
    /// as signed-out rather than dropped, so "Chrome is busy" cannot masquerade as "no profiles".
    fn has_youtube_session(cookies: &Path) -> bool {
        let Ok(conn) = open_readonly(cookies) else { return false };
        let sql = "SELECT 1 FROM cookies WHERE name IN ('SAPISID', '__Secure-3PAPISID') \
                   AND (host_key = 'youtube.com' OR host_key = '.youtube.com') \
                   AND top_frame_site_key = '' LIMIT 1";
        conn.query_row(sql, [], |_| Ok(())).is_ok()
    }

    /// Open Chrome's live store without disturbing it.
    ///
    /// Read-only against the original is the fast path and works with Chrome running. Note this
    /// is deliberately *not* `immutable=1`: that flag tells SQLite to ignore the rollback journal,
    /// and this database runs in `journal_mode=delete`, so a hot journal would be read as a
    /// mid-transaction page view. It appears to work, which is what makes it a bad idea.
    fn open_readonly(path: &Path) -> Result<rusqlite::Connection, String> {
        let conn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("Could not open Chrome's cookie database: {e}"))?;
        let _ = conn.busy_timeout(Duration::from_millis(1500));
        Ok(conn)
    }

    /// A private copy, for the case where the original cannot be opened — a hot rollback journal
    /// needs write access to replay, which a read-only handle cannot do. Copying the journal with
    /// it and opening the copy read-write lets SQLite recover against our file, never Chrome's.
    struct Snapshot(PathBuf);

    impl Snapshot {
        fn take(profile: &Path) -> Result<Self, String> {
            let dir = std::env::temp_dir().join(format!("limusic-cookies-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir: {e}"))?;
            std::fs::copy(profile.join("Cookies"), dir.join("Cookies"))
                .map_err(|e| format!("Could not read Chrome's cookie database: {e}"))?;
            let journal = profile.join("Cookies-journal");
            if journal.is_file() {
                let _ = std::fs::copy(journal, dir.join("Cookies-journal"));
            }
            Ok(Self(dir))
        }
    }

    impl Drop for Snapshot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Rows for youtube.com, first-party only.
    ///
    /// `top_frame_site_key = ''` is load-bearing, not tidying. CHIPS-partitioned third-party
    /// cookies share a name with the first-party one and vastly outnumber it — on a real profile
    /// here, 344 of 364 YouTube rows are partitioned, and `VISITOR_INFO1_LIVE` has 85 partitioned
    /// rows and no first-party row at all. Without the filter, one of those is picked arbitrarily
    /// and sent as if it were first-party.
    fn youtube_rows(conn: &rusqlite::Connection) -> Result<Vec<(String, String, Vec<u8>)>, String> {
        // Chrome stores time as microseconds since 1601-01-01.
        let now_chrome = (crate::db::now_secs() + 11_644_473_600) * 1_000_000;
        let select = "SELECT host_key, name, encrypted_value FROM cookies \
                      WHERE (host_key = 'youtube.com' OR host_key LIKE '%.youtube.com') \
                        AND (has_expires = 0 OR expires_utc > ?1)";

        // `top_frame_site_key` predates Chrome 100 but not every Chrome ever shipped; fall back
        // rather than fail on a store old enough to lack it.
        let partitioned = format!("{select} AND top_frame_site_key = ''");
        let sql = if conn.prepare(&partitioned).is_ok() { partitioned } else { select.to_string() };

        let mut stmt = conn.prepare(&sql).map_err(|e| format!("cookie query: {e}"))?;
        let rows = stmt
            .query_map([now_chrome], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| format!("cookie query: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// The `Cookie:` header for `profile_dir`, ready for `AppState::sign_in`.
    pub fn youtube_cookie_header(profile_dir: &str) -> Result<String, String> {
        // The UI hands back a directory name from `profiles()`. Treat it as untrusted: a path
        // separator here would otherwise read a cookie store from anywhere on disk.
        if profile_dir.is_empty() || profile_dir.contains('/') || profile_dir.contains("..") {
            return Err("Invalid Chrome profile.".into());
        }
        let root = user_data_dir().ok_or("Could not locate the Chrome data directory.")?;
        let profile = root.join(profile_dir);
        if !profile.join("Cookies").is_file() {
            return Err(format!("Chrome profile {profile_dir:?} has no cookie store."));
        }

        let key = chrome_key()?;

        // Held alive for as long as the connection reads from it.
        let mut _snapshot = None;
        let conn = match open_readonly(&profile.join("Cookies")) {
            Ok(conn) => conn,
            Err(_) => {
                let snap = Snapshot::take(&profile)?;
                let conn = rusqlite::Connection::open(snap.0.join("Cookies"))
                    .map_err(|e| format!("Could not open Chrome's cookie database: {e}"))?;
                _snapshot = Some(snap);
                conn
            }
        };

        let rows = youtube_rows(&conn)?;
        if rows.is_empty() {
            return Err("That Chrome profile has no YouTube cookies. Open youtube.com in \
                        Chrome, sign in, then try again."
                .into());
        }

        let mut jar = Vec::new();
        let mut undecryptable = 0usize;
        for (host, name, blob) in rows {
            // A single bad row must not fail the import: stores accumulate junk, and whether the
            // cookies that matter arrived is decided by `sign_in` validating the result.
            match decrypt(&blob, &key, &host) {
                Some(value) if is_cookie_octet_safe(&value) => jar.push((host, name, value)),
                _ => undecryptable += 1,
            }
        }

        let header = assemble(jar);
        if header.is_empty() && undecryptable > 0 {
            return Err("Chrome's cookies could not be decrypted — its saved key may have \
                        changed. Use the regular sign-in instead."
                .into());
        }
        Ok(header)
    }
}

/// The cipher and the header shape. Free of platform and of `AppState`, so it is testable
/// everywhere — which matters because CI runs on Linux and this is the part worth pinning.
mod crypto {
    use std::collections::BTreeMap;

    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use sha2::{Digest, Sha256};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    /// Chromium's macOS KDF parameters. Compile-time constants in `os_crypt_mac.mm`, not secrets.
    /// Linux uses the same salt with **one** iteration — do not reuse this constant there.
    const SALT: &[u8] = b"saltysalt";
    const ITERATIONS: u32 = 1003;
    /// Chromium encrypts with an IV of sixteen spaces rather than a random one.
    const IV: [u8; 16] = [b' '; 16];
    const V10: &[u8] = b"v10";
    const V20: &[u8] = b"v20";

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn derive_key(password: &[u8]) -> [u8; 16] {
        let mut key = [0u8; 16];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, SALT, ITERATIONS, &mut key);
        key
    }

    /// One `encrypted_value` blob back to its plaintext, or `None` for any row we cannot trust.
    ///
    /// Chrome 131 (`meta.version` 24, which is what ships here) prepends `SHA256(host_key)` to the
    /// value before encrypting, so a stolen blob cannot be replanted under another domain.
    /// Verifying that prefix rather than guessing at it also makes a wrong key fail cleanly
    /// instead of yielding plausible-looking garbage that would then be sent to Google as a login.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn decrypt(blob: &[u8], key: &[u8; 16], host_key: &str) -> Option<String> {
        if blob.starts_with(V20) {
            // App-bound encryption: the key lives behind a Chrome-signed service, deliberately out
            // of reach of other processes. Nothing to decrypt with.
            return None;
        }
        if !blob.starts_with(V10) {
            // Pre-encryption Chromium wrote values in the clear.
            return String::from_utf8(blob.to_vec()).ok();
        }

        let plain = Aes128CbcDec::new_from_slices(key, &IV)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(blob.get(V10.len()..)?)
            .ok()?;

        // Older rows carry no prefix; both layouts coexist for as long as an old cookie survives.
        if plain.len() >= 32 && plain[..32] == Sha256::digest(host_key.as_bytes())[..] {
            return Some(String::from_utf8_lossy(&plain[32..]).into_owned());
        }
        String::from_utf8(plain).ok()
    }

    /// RFC 6265 cookie-octet. The decrypted value goes straight into an HTTP `Cookie:` header, so
    /// a corrupt row carrying `;` would silently split one cookie into two, and CR/LF would be
    /// header injection. Failing one cookie closed beats failing the whole request.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn is_cookie_octet_safe(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
    }

    /// Fold rows into a header the way `session.rs::youtube_cookie_header` does, so a webview
    /// sign-in and an imported one hand `sign_in` the same shape: youtube.com only (google.com
    /// deliberately dropped — this header is sent to YouTube), most specific domain wins a name
    /// collision. Kept here rather than calling session.rs so this module stays free of `tauri`
    /// and its tests can run on Linux; the cases below mirror that function's own tests.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn assemble(mut rows: Vec<(String, String, String)>) -> String {
        rows.sort_by_key(|(host, _, _)| host.trim_start_matches('.').len());
        let mut jar = BTreeMap::new();
        for (host, name, value) in rows {
            let domain = host.trim_start_matches('.');
            if domain == "youtube.com" || domain.ends_with(".youtube.com") {
                jar.insert(name, value);
            }
        }
        jar.into_iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aes::cipher::{block_padding::Pkcs7 as EncPad, BlockEncryptMut};

        /// Build a row exactly the way Chrome 131 writes one: `SHA256(host)` ahead of the value,
        /// PKCS#7-padded, AES-128-CBC under the space IV, tagged `v10`.
        fn chrome_row(key: &[u8; 16], host: &str, value: &str, prefix: bool) -> Vec<u8> {
            let mut plain = if prefix { Sha256::digest(host.as_bytes()).to_vec() } else { vec![] };
            plain.extend_from_slice(value.as_bytes());
            let mut blob = V10.to_vec();
            blob.extend(
                cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &IV)
                    .unwrap()
                    .encrypt_padded_vec_mut::<EncPad>(&plain),
            );
            blob
        }

        #[test]
        fn decrypts_a_chrome_131_row_and_strips_the_domain_hash() {
            let key = derive_key(b"test-password");
            let blob = chrome_row(&key, ".youtube.com", "secret-sapisid-value", true);
            assert_eq!(decrypt(&blob, &key, ".youtube.com").unwrap(), "secret-sapisid-value");
        }

        /// Rows written before the prefix landed still have to work — both layouts coexist in one
        /// database for as long as an old cookie survives.
        #[test]
        fn decrypts_a_legacy_row_without_the_prefix() {
            let key = derive_key(b"test-password");
            let blob = chrome_row(&key, ".youtube.com", "older-value", false);
            assert_eq!(decrypt(&blob, &key, ".youtube.com").unwrap(), "older-value");
        }

        /// The prefix is bound to the host, so a blob replanted under another domain must not
        /// decrypt cleanly into a usable value.
        #[test]
        fn a_row_moved_to_another_host_does_not_verify() {
            let key = derive_key(b"test-password");
            let blob = chrome_row(&key, ".youtube.com", "secret-sapisid-value", true);
            // Wrong host: the hash no longer matches, so the prefix is not stripped and the
            // caller sees the raw bytes rather than a clean value it would send to Google.
            let got = decrypt(&blob, &key, ".evil.com");
            assert!(got.is_none() || !got.unwrap().starts_with("secret"));
        }

        /// A wrong Keychain password must fail rather than return plausible garbage.
        #[test]
        fn a_wrong_key_does_not_silently_succeed() {
            let right = derive_key(b"right");
            let wrong = derive_key(b"wrong");
            let blob = chrome_row(&right, ".youtube.com", "secret-sapisid-value", true);
            let got = decrypt(&blob, &wrong, ".youtube.com");
            assert!(got.is_none() || !got.unwrap().contains("secret"));
        }

        #[test]
        fn app_bound_encryption_is_skipped_not_guessed() {
            let mut blob = V20.to_vec();
            blob.extend_from_slice(&[0u8; 32]);
            assert!(decrypt(&blob, &[0u8; 16], ".youtube.com").is_none());
        }

        #[test]
        fn a_truncated_blob_does_not_panic() {
            let key = derive_key(b"x");
            assert!(decrypt(b"v10", &key, ".youtube.com").is_none());
            assert!(decrypt(b"v10\x01\x02", &key, ".youtube.com").is_none());
        }

        /// Real cookies carry `=`, `/`, `-` and `|`; a value may never carry the bytes that would
        /// break, split or inject into the header.
        #[test]
        fn cookie_octet_guard_accepts_real_values_and_rejects_separators() {
            assert!(is_cookie_octet_safe("AbC-123_x/y=="));
            assert!(is_cookie_octet_safe("f6g=1|tz=Asia.Jakarta"));
            for bad in ["a;b", "a,b", "a b", "a\"b", "a\\b", "a\rb", "a\nb", "a\0b", ""] {
                assert!(!is_cookie_octet_safe(bad), "should reject {bad:?}");
            }
        }

        /// Mirrors `session.rs::keeps_the_youtube_jar_and_drops_everything_else`.
        #[test]
        fn keeps_the_youtube_jar_and_drops_everything_else() {
            let header = assemble(vec![
                (".youtube.com".into(), "SAPISID".into(), "abc".into()),
                (".youtube.com".into(), "SID".into(), "def".into()),
                ("music.youtube.com".into(), "VISITOR_INFO1_LIVE".into(), "xyz".into()),
                (".google.com".into(), "SAPISID".into(), "notthisone".into()),
            ]);
            assert!(header.contains("SAPISID=abc"));
            assert!(header.contains("SID=def"));
            assert!(header.contains("VISITOR_INFO1_LIVE=xyz"));
            assert!(!header.contains("notthisone"));
        }

        /// The most specific domain wins, the way a browser resolves a collision.
        #[test]
        fn the_most_specific_domain_wins_a_collision() {
            let header = assemble(vec![
                ("music.youtube.com".into(), "PREF".into(), "specific".into()),
                (".youtube.com".into(), "PREF".into(), "general".into()),
            ]);
            assert_eq!(header, "PREF=specific");
        }
    }
}
