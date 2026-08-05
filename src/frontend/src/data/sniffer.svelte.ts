import { fetcher } from "../utils/fetcher";

export type SNISnifferConfig = {
	enabled: boolean;
	queue_num: number;
	max_queue_len: number;
	max_packet_len: number;
	verdict_timeout_ns: number;
	enable_tls: boolean;
	enable_http: boolean;
	enable_http2: boolean;
	allowed_ports: number[];
	additional_ttl_ns: number;
	log_dns_mismatch: boolean;
};

export type SNISnifferStats = {
	packets_total: number;
	hits_total: number;
	misses_total: number;
	parse_failures: number;
	empty_payload_total: number;
	stitched_hits: number;
	packets_per_sec: number;
	started_at: string;
	active: boolean;
};

export type SNISnifferObservation = {
	ip: string;
	domain: string;
	observed: string;
	expires_in_ns: number;
};

export const snifferApi = {
	getConfig: () => fetcher.get<SNISnifferConfig>("/sniffer/config"),

	updateConfig: (config: SNISnifferConfig, save: boolean) =>
		fetcher.put<SNISnifferConfig>(
			`/sniffer/config${save ? "?save=true" : ""}`,
			config,
		),

	getStats: () => fetcher.get<SNISnifferStats>("/sniffer/stats"),

	getRecent: (limit = 50) =>
		fetcher.get<{ observations: SNISnifferObservation[] }>(
			`/sniffer/recent?limit=${limit}`,
		),
};
