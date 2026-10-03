// ---------------------------------------------------------------------------
// Transport (injectable for tests)
// ---------------------------------------------------------------------------

import { Client as LdapClient } from "ldapts";
import { HOST_EXEC_TIMEOUT_MS } from "../common.js";

export interface AdEntry {
  dn: string;
  attrs: Record<string, string[]>;
}

export interface AdTransport {
  connect(url: string): Promise<void>;
  bind(dn: string, password: string): Promise<void>;
  /** Search returning normalized entries (attribute names as returned by the server). */
  search(base: string, filter: string, attributes: string[], sizeLimit?: number): Promise<AdEntry[]>;
  /** Raw attribute names as returned (for ranged-retrieval markers). */
  searchRaw(base: string, filter: string, attributes: string[], sizeLimit?: number): Promise<{ dn: string; attrs: Record<string, string[]> }[]>;
  close(): Promise<void>;
}

function normalizeEntry(dn: string, raw: Record<string, unknown>): AdEntry {
  const attrs: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k === "dn") continue;
    const vals = Array.isArray(v) ? v : [v];
    attrs[k] = vals.map((x) => (Buffer.isBuffer(x) ? (x as Buffer).toString("base64") : String(x)));
  }
  return { dn, attrs };
}

export function createAdTransport(): AdTransport {
  let client: LdapClient | undefined;
  const api: AdTransport = {
    async connect(url) {
      client = new LdapClient({ url, timeout: HOST_EXEC_TIMEOUT_MS, connectTimeout: HOST_EXEC_TIMEOUT_MS });
    },
    async bind(dn, password) {
      if (!client) throw new Error("[ad] not connected");
      await client.bind(dn, password);
    },
    async search(base, filter, attributes, sizeLimit = 2000) {
      const raw = await api.searchRaw(base, filter, attributes, sizeLimit);
      return raw.map((e) => normalizeEntry(e.dn, e.attrs));
    },
    async searchRaw(base, filter, attributes, sizeLimit = 2000) {
      if (!client) throw new Error("[ad] not connected");
      const res = await client.search(base, {
        scope: "sub",
        filter,
        attributes,
        sizeLimit,
        timeLimit: 30,
        paged: false,
      });
      return res.searchEntries.map((e) => {
        const attrs: Record<string, string[]> = {};
        for (const [k, v] of Object.entries(e)) {
          if (k === "dn") continue;
          const vals = Array.isArray(v) ? v : [v];
          attrs[k] = vals.map((x) => (Buffer.isBuffer(x) ? (x as Buffer).toString("base64") : String(x)));
        }
        return { dn: e.dn, attrs };
      });
    },
    async close() {
      try {
        await client?.unbind();
      } catch {
        /* best effort */
      }
      client = undefined;
    },
  };
  return api;
}
