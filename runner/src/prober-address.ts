/**
 * Address policy shared by the prober and its DNS-pinned transport.
 *
 * Kept apart from prober-net.ts so the resolver/pinning code stays within the
 * repository's per-file budget; the rules themselves are the same ones
 * validateProbeTarget has always applied before any packet is sent.
 */

/** Literal private-range / loopback host, by name or address (pre-resolution guard). */
export const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[::1\]|::1$)/i;

/** True when `host` is a literal private-range or loopback address/name. */
export function isPrivateOrLoopbackHost(host: string): boolean {
  return PRIVATE_HOST.test(host.toLowerCase());
}

/**
 * True when every host is private/loopback (and there is at least one).
 *
 * Local sandbox mode skips ownership verification for a private target, so it may only
 * widen the prober to private hosts when the WHOLE scope is private: a loopback target
 * combined with a public scope host must not inherit the sandbox bypass.
 */
export function allHostsPrivateOrLoopback(hosts: readonly string[]): boolean {
  return hosts.length > 0 && hosts.every((h) => isPrivateOrLoopbackHost(h));
}