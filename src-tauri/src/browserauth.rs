//! Signing in from a browser's own Google session, and healing such a session later.
//!
//! [`crate::browsercookies`] knows how to read Chrome's cookie store and nothing else; this is
//! the half that knows about `AppState`, the `accounts` table and the sign-in seam. Keeping them
//! apart is what lets the cipher and header code be unit-tested on CI, which runs Linux and so
//! can never exercise the Keychain or a real profile.

use std::sync::Arc;

use crate::browsercookies;
use crate::state::{AppState, SignInOutcome};

/// Where an account's session came from, stored as JSON in `account_sources.source`.
///
/// `browser` is a string rather than an enum so a store written by a future build that supports
/// Firefox round-trips through an older one instead of failing to deserialize and silently
/// losing the provenance.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BrowserRef {
    pub browser: String,
    pub profile: String,
}

pub const CHROME: &str = "chrome";

/// What a re-import should do with the jar it just read.
#[derive(Debug, PartialEq)]
pub(crate) enum Heal {
    /// Fresh cookies for the same account — sign in with them.
    Apply,
    /// The browser profile now holds a *different* Google account. Doing nothing is the whole
    /// point: healing must never move the user to an account they did not pick.
    DifferentAccount,
    /// Byte-identical jar. The browser has not rotated anything, so there is nothing to heal
    /// with and no request worth spending.
    Unchanged,
}

pub(crate) fn heal_decision(current: &str, fresh: &str) -> Heal {
    if innertube::cookie_sapisid(fresh) != innertube::cookie_sapisid(current) {
        return Heal::DifferentAccount;
    }
    if crate::session::same_jar(fresh, current) {
        return Heal::Unchanged;
    }
    Heal::Apply
}

/// Read `target`'s Google session and sign in with it.
///
/// The header exists only inside this function and the `sign_in` call: it is never serialized
/// toward the renderer, which keeps the invariant that auth material stays in Rust
/// (`commands.rs::UI_SETTINGS`).
pub async fn sign_in_from_browser(
    state: &Arc<AppState>,
    target: BrowserRef,
) -> Result<SignInOutcome, String> {
    let profile = target.profile.clone();
    // SQLite plus, on the first call of the run, a Keychain prompt — neither belongs on the async
    // runtime, where a modal dialog would stall every other task.
    let header = tauri::async_runtime::spawn_blocking(move || {
        browsercookies::youtube_cookie_header(&profile)
    })
    .await
    .map_err(|e| format!("Chrome import failed: {e}"))??;

    let id = crate::db::account_key(&header).ok_or(
        "That Chrome profile isn't signed in to YouTube. Open youtube.com in Chrome, sign in, \
         then try again.",
    )?;

    // `expect_account: None` — this is a user-initiated sign-in like the webview's, not a heal,
    // so landing on whichever account Chrome holds is exactly what was asked for.
    let outcome = state.sign_in(header, None).await?;

    // Only once the cookie has actually authenticated: a rejected one must not teach the healer
    // to come back to a profile that does not work.
    if let Ok(source) = serde_json::to_string(&target) {
        state.db.set_account_source(&id, &source);
    }
    Ok(outcome)
}

/// Heal a browser-imported account by re-importing from the browser it came from.
///
/// `true` means handled — stop. `false` means this is not an imported account, or the re-import
/// had nothing better to offer, and the caller should fall through to the login-webview heal.
pub async fn try_heal(state: &Arc<AppState>) -> bool {
    let Some(current) = state.it.cookie() else { return false };
    let Some(id) = crate::db::account_key(&current) else { return false };
    // No row means a webview sign-in; that heal is the caller's job, not ours.
    let Some(raw) = state.db.get_account_source(&id) else { return false };
    let Ok(target) = serde_json::from_str::<BrowserRef>(&raw) else { return false };
    if target.browser != CHROME {
        return false;
    }

    let profile = target.profile.clone();
    let fresh = match tauri::async_runtime::spawn_blocking(move || {
        browsercookies::youtube_cookie_header(&profile)
    })
    .await
    {
        Ok(Ok(header)) => header,
        // Chrome uninstalled, profile deleted, Keychain refused — all ordinary, and all mean
        // "let the webview try". Logged at debug because a failing heal is not a user-facing
        // event; they are already looking at a sign-in prompt.
        other => {
            tracing::debug!(?other, "browser re-import had nothing to offer");
            return false;
        }
    };

    match heal_decision(&current, &fresh) {
        Heal::DifferentAccount => {
            tracing::warn!(
                profile = %target.profile,
                "that Chrome profile now holds a different Google account; not healing"
            );
            false
        }
        Heal::Unchanged => {
            tracing::debug!("Chrome's jar is unchanged; nothing to heal with");
            false
        }
        Heal::Apply => {
            // `sign_in` re-checks the account under its own lock, where nothing can move
            // underneath it. The check in `heal_decision` only saves the round trip.
            let expect = innertube::cookie_sapisid(&current).map(str::to_owned);
            match state.sign_in(fresh, expect.as_deref()).await {
                Ok(_) => {
                    tracing::info!("re-minted the session from Chrome");
                    true
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Chrome re-import did not authenticate");
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "SAPISID=account-a; SID=one";
    const A_ROTATED: &str = "SAPISID=account-a; SID=two";
    const B: &str = "SAPISID=account-b; SID=one";

    /// The safety property: a profile that has been signed into someone else must never be
    /// applied, however fresh its cookies are.
    #[test]
    fn a_different_account_is_never_applied() {
        assert_eq!(heal_decision(A, B), Heal::DifferentAccount);
    }

    #[test]
    fn a_rotated_jar_for_the_same_account_heals() {
        assert_eq!(heal_decision(A, A_ROTATED), Heal::Apply);
    }

    /// Chrome only rotates while it is running; with it closed the re-import returns what we
    /// already have, and spending a sign-in on that would be pure cost.
    #[test]
    fn an_unchanged_jar_is_left_alone() {
        assert_eq!(heal_decision(A, A), Heal::Unchanged);
    }

    /// Order differs between the webview export (sorted) and the transport's rotation merge
    /// (appended), so ordering alone must not read as a change.
    #[test]
    fn reordering_is_not_a_change() {
        assert_eq!(heal_decision("SAPISID=a; SID=one", "SID=one; SAPISID=a"), Heal::Unchanged);
    }

    /// A jar with no SAPISID is not a session; it must not compare equal to a real one.
    #[test]
    fn a_jar_without_sapisid_is_a_different_account() {
        assert_eq!(heal_decision(A, "SID=one"), Heal::DifferentAccount);
    }

    #[test]
    fn browser_ref_round_trips() {
        let target = BrowserRef { browser: CHROME.into(), profile: "Profile 2".into() };
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(serde_json::from_str::<BrowserRef>(&json).unwrap(), target);
    }
}
