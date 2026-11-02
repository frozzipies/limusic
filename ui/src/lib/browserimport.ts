// What the "Sign in with Chrome" button should do, given what Rust found. Split out of
// AccountMenu.svelte because the branches are the whole behaviour of the feature and the only
// way to exercise them in the component is to own three Chrome profiles in three states.
//
// Deliberately pure: no `api`, no stores, no DOM. See `browserimport.check.ts`.

import type { BrowserSignInStatus } from './api';

export type ImportAction =
	/** Not offered at all: wrong platform, no Chrome, or no profile signed in to YouTube. */
	| { kind: 'hidden' }
	/** Exactly one usable profile — skip the picker, it would be a dialog with one button. */
	| { kind: 'direct'; dir: string }
	/** Several usable profiles; ask which. */
	| { kind: 'pick' }
	/** Chrome is here but unusable; `message` comes from Rust and is already user-facing. */
	| { kind: 'problem'; message: string };

export function importAction(status: BrowserSignInStatus | null): ImportAction {
	// `null` is the fetch having failed. Hiding beats showing a button that cannot work.
	if (!status?.supported) return { kind: 'hidden' };

	const ready = status.profiles.filter((p) => p.signed_in);
	if (ready.length === 1) return { kind: 'direct', dir: ready[0].dir };
	if (ready.length > 1) return { kind: 'pick' };

	// Supported, nothing usable. A `problem` from Rust is worth showing; "Chrome is installed but
	// you have never signed in to YouTube in it" is not a problem, it is just not for this user.
	return status.problem ? { kind: 'problem', message: status.problem } : { kind: 'hidden' };
}

/** Signed-out profiles are listed in the picker, greyed, so the list matches what Chrome shows. */
export function pickerRows(status: BrowserSignInStatus | null) {
	return status?.profiles ?? [];
}
