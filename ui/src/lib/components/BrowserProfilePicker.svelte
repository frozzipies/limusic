<script lang="ts">
	// Which Chrome profile to take the Google session from. Only ever opened when more than one
	// profile is signed in to YouTube — with a single one `importAction` skips straight to the
	// import, because a dialog with one button asks nothing.
	//
	// Driven by props rather than by a flag in `player.svelte.ts`: it belongs to the account menu
	// and nothing else needs to open it.
	import { HugeiconsIcon } from '@hugeicons/svelte';
	import { UserCircleIcon } from '@hugeicons/core-free-icons';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import type { BrowserProfile } from '$lib/api';
	import { t } from '$lib/i18n.svelte';

	let {
		open = $bindable(false),
		profiles = [],
		importing = null,
		onpick
	}: {
		open?: boolean;
		profiles?: BrowserProfile[];
		importing?: string | null;
		onpick: (dir: string) => void;
	} = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="gap-0 overflow-hidden p-0 sm:max-w-md">
		<div class="border-b px-5 py-4">
			<Dialog.Title class="text-lg font-semibold">{t('nav.chrome_pick_profile')}</Dialog.Title>
			<Dialog.Description class="mt-1 text-xs text-muted-foreground">
				{t('nav.chrome_pick_profile_desc')}
			</Dialog.Description>
		</div>

		<div class="max-h-[26rem] min-h-32 overflow-y-auto p-2">
			{#each profiles as profile (profile.dir)}
				<!-- Signed-out profiles are listed but inert, so the list matches what Chrome shows
				     and a missing profile reads as "not signed in" rather than as a bug. -->
				<button
					type="button"
					onclick={() => onpick(profile.dir)}
					disabled={!profile.signed_in || importing !== null}
					class="flex w-full cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
				>
					<span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted">
						<HugeiconsIcon icon={UserCircleIcon} class="h-6 w-6 text-muted-foreground" />
					</span>
					<span class="min-w-0 flex-1">
						<span class="block truncate text-sm font-medium">{profile.name}</span>
						<span class="block truncate text-xs text-muted-foreground">
							{#if !profile.signed_in}
								{t('nav.chrome_profile_signed_out')}
							{:else if profile.email}
								{profile.email}
							{:else}
								{profile.dir}
							{/if}
						</span>
					</span>
					{#if importing === profile.dir}
						<span class="shrink-0 text-xs text-muted-foreground">{t('common.loading')}</span>
					{/if}
				</button>
			{/each}
		</div>

		<!-- The Keychain prompt is a macOS password dialog appearing out of nowhere unless it is
		     explained before we cause it. -->
		<p class="border-t px-5 py-3 text-[11px] leading-relaxed text-muted-foreground">
			{t('nav.chrome_keychain_hint')}
		</p>

		<div class="flex justify-end border-t px-5 py-3">
			<Button variant="outline" size="sm" onclick={() => (open = false)} disabled={importing !== null}>
				{t('common.cancel')}
			</Button>
		</div>
	</Dialog.Content>
</Dialog.Root>
