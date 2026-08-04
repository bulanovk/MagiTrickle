<script lang="ts">
	import { onDestroy, onMount } from "svelte";

	import {
		snifferApi,
		type SNISnifferConfig,
		type SNISnifferObservation,
		type SNISnifferStats,
	} from "../../data/sniffer.svelte";
	import { t } from "../../data/locale.svelte";

	let config = $state<SNISnifferConfig | null>(null);
	let stats = $state<SNISnifferStats | null>(null);
	let observations = $state<SNISnifferObservation[]>([]);
	let saveOnUpdate = $state(true);
	let loading = $state(false);
	let error = $state<string | null>(null);
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	async function refreshAll() {
		loading = true;
		error = null;
		try {
			const [cfg, st, rec] = await Promise.all([
				snifferApi.getConfig(),
				snifferApi.getStats(),
				snifferApi.getRecent(50),
			]);
			config = cfg;
			stats = st;
			observations = rec.observations;
		} catch (e) {
			error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	async function saveConfig() {
		if (!config) return;
		loading = true;
		try {
			config = await snifferApi.updateConfig(config, saveOnUpdate);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	function fmtNumber(n: number): string {
		return n.toLocaleString();
	}

	function fmtDuration(ns: number): string {
		if (ns <= 0) return "—";
		const sec = Math.floor(ns / 1e9);
		if (sec < 60) return `${sec}s`;
		const min = Math.floor(sec / 60);
		if (min < 60) return `${min}m`;
		const hr = Math.floor(min / 60);
		return `${hr}h ${min % 60}m`;
	}

	function fmtTime(iso: string): string {
		try {
			const d = new Date(iso);
			if (isNaN(d.getTime())) return iso;
			return d.toLocaleTimeString();
		} catch {
			return iso;
		}
	}

	onMount(() => {
		refreshAll();
		pollTimer = setInterval(refreshAll, 5000);
	});

	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});
</script>

<div class="sniffer">
	<header>
		<h2>{t("SNI sniffer")}</h2>
		<p class="muted">
			{t("NFQUEUE-based domain extractor for traffic that bypasses the DNS-MITM proxy.")}
		</p>
	</header>

	{#if error}
		<div class="alert error">{error}</div>
	{/if}

	{#if config}
		<section class="card">
			<h3>{t("Configuration")}</h3>
			<div class="grid">
				<label>
					<input type="checkbox" bind:checked={config.enabled} />
					<span>{t("Enabled")}</span>
					</label>
					<label>
						<input type="checkbox" bind:checked={config.enable_tls} />
						<span>{t("Parse TLS ClientHello")}</span>
					</label>
				<label>
					<input type="checkbox" bind:checked={config.enable_http} />
					<span>{t("Parse HTTP/1.1 Host")}</span>
				</label>
				<label>
					<input type="checkbox" bind:checked={config.enable_http2} />
					<span>{t("Parse HTTP/2 :authority")}</span>
				</label>
			</div>
			<div class="grid">
				<label>
					<span>{t("NFQUEUE number")}</span>
					<input type="number" min="0" max="65535" bind:value={config.queue_num} />
				</label>
				<label>
					<span>{t("Max queue length")}</span>
					<input
						type="number"
						min="64"
						max="65536"
						bind:value={config.max_queue_len}
					/>
				</label>
				<label>
					<span>{t("Max packet bytes")}</span>
					<input
						type="number"
						min="512"
						max="131072"
						bind:value={config.max_packet_len}
					/>
				</label>
				<label>
					<span>{t("Verdict timeout (ms)")}</span>
					<input
						type="number"
						min="1"
						max="5000"
						value={Math.round(config.verdict_timeout_ns / 1e6)}
						oninput={(e) => {
							const v = Number((e.target as HTMLInputElement).value);
							if (!isNaN(v)) config!.verdict_timeout_ns = Math.max(1, v) * 1e6;
						}}
					/>
				</label>
				<label>
					<span>{t("Additional TTL (s)")}</span>
					<input
						type="number"
						min="0"
						max="86400"
						value={Math.round(config.additional_ttl_ns / 1e9)}
						oninput={(e) => {
							const v = Number((e.target as HTMLInputElement).value);
							if (!isNaN(v)) config!.additional_ttl_ns = Math.max(0, v) * 1e9;
						}}
					/>
				</label>
			</div>
			<div class="actions">
				<label class="inline">
					<input type="checkbox" bind:checked={saveOnUpdate} />
					<span>{t("Persist to config.yaml")}</span>
				</label>
				<button class="primary" onclick={saveConfig} disabled={loading}>
					{t("Apply")}
				</button>
			</div>
			<p class="muted small">
				{t(
					"Changes take effect after MagiTrickle restart; the sniffer runs as a background goroutine and is not hot-reloaded.",
				)}
			</p>
		</section>
	{/if}

	{#if stats}
		<section class="card">
			<h3>{t("Live counters")}</h3>
			<div class="counters">
				<div class="counter">
					<span class="label">{t("Packets")}</span>
					<span class="value">{fmtNumber(stats.packets_total)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Packets/sec")}</span>
					<span class="value">{stats.packets_per_sec.toFixed(1)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Hits")}</span>
					<span class="value">{fmtNumber(stats.hits_total)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Misses")}</span>
					<span class="value">{fmtNumber(stats.misses_total)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Parse failures")}</span>
					<span class="value">{fmtNumber(stats.parse_failures)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Empty payload")}</span>
					<span class="value">{fmtNumber(stats.empty_payload_total)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Stitched hits")}</span>
					<span class="value">{fmtNumber(stats.stitched_hits)}</span>
				</div>
				<div class="counter">
					<span class="label">{t("Active")}</span>
					<span class="value">{stats.active ? t("yes") : t("no")}</span>
				</div>
			</div>
		</section>
	{/if}

	<section class="card">
		<h3>{t("Recent observations")}</h3>
		{#if observations.length === 0}
			<p class="muted">{t("No SNI observations recorded yet.")}</p>
		{:else}
			<table>
				<thead>
					<tr>
						<th>{t("Time")}</th>
						<th>{t("IP")}</th>
						<th>{t("Domain")}</th>
						<th>{t("Expires in")}</th>
					</tr>
				</thead>
				<tbody>
					{#each observations as obs (obs.ip + obs.observed)}
						<tr>
							<td>{fmtTime(obs.observed)}</td>
							<td class="mono">{obs.ip}</td>
							<td>{obs.domain}</td>
							<td>{fmtDuration(obs.expires_in_ns)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>
</div>

<style>
	.sniffer {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding: 0.5rem 0;
	}
	.card {
		background: var(--bg-1, rgba(255, 255, 255, 0.03));
		border: 1px solid var(--border-1, rgba(255, 255, 255, 0.08));
		border-radius: 8px;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	header h2 {
		margin: 0 0 0.25rem;
	}
	.muted {
		opacity: 0.7;
	}
	.small {
		font-size: 0.85em;
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
		gap: 0.75rem;
	}
	.grid label {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		font-size: 0.9em;
	}
	.actions label.inline {
		flex-direction: row;
		align-items: center;
		gap: 0.4rem;
	}
	.counters {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
		gap: 0.75rem;
	}
	.counter {
		display: flex;
		flex-direction: column;
		padding: 0.5rem 0.75rem;
		background: rgba(255, 255, 255, 0.04);
		border-radius: 6px;
	}
	.counter .label {
		font-size: 0.75em;
		opacity: 0.7;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.counter .value {
		font-size: 1.4em;
		font-weight: 600;
	}
	.actions {
		display: flex;
		align-items: center;
		gap: 1rem;
	}
	button.primary {
		padding: 0.4rem 1rem;
		border-radius: 4px;
		background: var(--blue-light-extra, #4a9eff);
		color: white;
		border: none;
		cursor: pointer;
	}
	button.primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	input[type="number"] {
		width: 100%;
		padding: 0.3rem 0.5rem;
		background: rgba(0, 0, 0, 0.2);
		color: inherit;
		border: 1px solid var(--border-1, rgba(255, 255, 255, 0.08));
		border-radius: 4px;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.9em;
	}
	th,
	td {
		text-align: left;
		padding: 0.4rem 0.6rem;
		border-bottom: 1px solid var(--border-1, rgba(255, 255, 255, 0.06));
	}
	th {
		opacity: 0.7;
		font-weight: 500;
	}
	.mono {
		font-family: ui-monospace, monospace;
	}
	.alert {
		padding: 0.6rem 0.9rem;
		border-radius: 6px;
	}
	.alert.error {
		background: rgba(255, 80, 80, 0.15);
		border: 1px solid rgba(255, 80, 80, 0.4);
	}
</style>
