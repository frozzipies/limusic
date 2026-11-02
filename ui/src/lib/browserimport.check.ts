// Self-check for the "Sign in with Chrome" branch picker in `browserimport.ts`. Same deal as
// `dnd.check.ts` — no test runner in `ui/`, node runs TypeScript directly:
//
//     node --experimental-strip-types ui/src/lib/browserimport.check.ts
//
// Prints "ok" and exits 0, or throws on the first broken invariant. The dialog around this needs
// a DOM; deciding whether to show a button, skip straight through, or ask which profile does not
// — and the only other way to cover it is to own three Chrome profiles in three different states.
import { importAction } from './browserimport.ts';
import type { BrowserProfile, BrowserSignInStatus } from './api.ts';

function ok(cond: boolean, what: string): void {
	if (!cond) throw new Error(`FAIL: ${what}`);
}

const profile = (dir: string, signed_in: boolean): BrowserProfile => ({
	dir,
	name: dir,
	email: null,
	signed_in
});
const status = (p: BrowserProfile[], extra: Partial<BrowserSignInStatus> = {}) =>
	({ supported: true, profiles: p, problem: null, ...extra }) as BrowserSignInStatus;

// Nothing to offer: the button must not appear at all rather than appear and fail.
ok(importAction(null).kind === 'hidden', 'a failed status fetch hides the button');
ok(
	importAction(status([], { supported: false })).kind === 'hidden',
	'an unsupported platform hides the button'
);
ok(importAction(status([])).kind === 'hidden', 'no profiles at all hides the button');
ok(
	importAction(status([profile('Default', false)])).kind === 'hidden',
	'Chrome installed but never signed in to YouTube hides the button'
);

// One usable profile goes straight through: a picker with a single row is a dialog that asks
// nothing, and this is the common case for anyone with one Chrome profile.
const one = importAction(status([profile('Default', true)]));
ok(one.kind === 'direct', 'exactly one signed-in profile imports directly');
ok(one.kind === 'direct' && one.dir === 'Default', 'and it carries that profile');

// Signed-out profiles must not drag a single usable one into the picker.
const mixed = importAction(
	status([profile('Default', true), profile('Profile 2', false), profile('Profile 3', false)])
);
ok(mixed.kind === 'direct', 'signed-out profiles do not force the picker');
ok(mixed.kind === 'direct' && mixed.dir === 'Default', 'and the usable one is chosen');

// Two or more and we have to ask — picking for the user here would sign them into the wrong
// Google account, which is the one mistake this feature must never make.
ok(
	importAction(status([profile('Default', true), profile('Profile 2', true)])).kind === 'pick',
	'two signed-in profiles open the picker'
);

// A real problem from Rust is worth surfacing; "no YouTube session" already resolved to hidden
// above, so this only fires for things the user can act on.
const problem = importAction(status([], { problem: 'Chrome is busy. Quit Chrome and try again.' }));
ok(problem.kind === 'problem', 'a reported problem surfaces');
ok(
	problem.kind === 'problem' && problem.message.includes('Quit Chrome'),
	'and keeps the message verbatim'
);

console.log('ok');
