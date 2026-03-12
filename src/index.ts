import { Hono } from "hono";
import { cdpPaymentMiddleware } from "x402-cdp";
import { describeRoute, openAPIRouteHandler } from "hono-openapi";

const app = new Hono<{ Bindings: Env }>();

// OpenAPI spec — must be before paymentMiddleware
app.get("/.well-known/openapi.json", openAPIRouteHandler(app, {
  documentation: {
    info: {
      title: "x402 DNS Lookup Service",
      description: "Look up DNS records and WHOIS/RDAP registration info for domains. Pay-per-use via x402 protocol on Base mainnet.",
      version: "1.0.0",
    },
    servers: [{ url: "https://dns.camelai.io" }],
  },
}));

app.use(
  cdpPaymentMiddleware(
    (env) => ({
      "GET /dns": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.005",
            network: "eip155:8453",
            payTo: env.SERVER_ADDRESS as `0x${string}`,
          },
        ],
        description: "Look up DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) for a domain",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            discoverable: true,
            inputSchema: {
              queryParams: {
                domain: {
                  type: "string",
                  description: "Domain name to look up (e.g. example.com)",
                  required: true,
                },
                type: {
                  type: "string",
                  description: "Specific record type: A, AAAA, MX, TXT, NS, CNAME, SOA. Omit for all.",
                  required: false,
                },
              },
            },
          },
        },
      },
      "GET /whois": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.01",
            network: "eip155:8453",
            payTo: env.SERVER_ADDRESS as `0x${string}`,
          },
        ],
        description: "Look up WHOIS/RDAP registration info for a domain",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            discoverable: true,
            inputSchema: {
              queryParams: {
                domain: {
                  type: "string",
                  description: "Domain name to look up (e.g. example.com)",
                  required: true,
                },
              },
            },
          },
        },
      },
    })
  )
);

// --- DNS endpoint ---

const RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"] as const;

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DnsResponse {
  Status: number;
  Answer?: DnsAnswer[];
}

async function queryDns(domain: string, type: string): Promise<DnsAnswer[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  const res = await fetch(url, {
    headers: { Accept: "application/dns-json" },
  });
  if (!res.ok) return [];
  const data = (await res.json()) as DnsResponse;
  return data.Answer || [];
}

app.get("/dns", describeRoute({
  description: "Look up DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) for a domain. Requires x402 payment ($0.005).",
  responses: {
    200: { description: "DNS records", content: { "application/json": { schema: { type: "object" } } } },
    400: { description: "Missing or invalid domain" },
    402: { description: "Payment required" },
  },
}), async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    return c.json({ error: "Missing required query parameter: domain" }, 400);
  }

  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domain)) {
    return c.json({ error: "Invalid domain name" }, 400);
  }

  const requestedType = c.req.query("type")?.toUpperCase();
  const types = requestedType && RECORD_TYPES.includes(requestedType as any)
    ? [requestedType]
    : [...RECORD_TYPES];

  const results = await Promise.all(
    types.map(async (type) => {
      const answers = await queryDns(domain, type);
      return { type, records: answers.map((a) => ({ value: a.data, ttl: a.TTL })) };
    })
  );

  const records: Record<string, { value: string; ttl: number }[]> = {};
  for (const r of results) {
    if (r.records.length > 0) {
      records[r.type] = r.records;
    }
  }

  return c.json({ domain, records });
});

// --- WHOIS/RDAP endpoint ---

interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, ...unknown[][]];
}

interface RdapNameserver {
  ldhName: string;
}

interface RdapResponse {
  ldhName?: string;
  status?: string[];
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: RdapNameserver[];
  secureDNS?: { delegationSigned?: boolean };
  [key: string]: unknown;
}

function extractVcardField(vcard: unknown[][], field: string): string | undefined {
  for (const entry of vcard) {
    if (entry[0] === field) {
      const value = entry[3];
      if (typeof value === "string") return value;
      if (Array.isArray(value)) return value.flat().filter(Boolean).join(", ");
    }
  }
  return undefined;
}

app.get("/whois", describeRoute({
  description: "Look up WHOIS/RDAP registration info for a domain. Requires x402 payment ($0.01).",
  responses: {
    200: { description: "WHOIS/RDAP registration info", content: { "application/json": { schema: { type: "object" } } } },
    400: { description: "Missing or invalid domain" },
    402: { description: "Payment required" },
    404: { description: "Domain not found in RDAP" },
    502: { description: "RDAP lookup failed" },
  },
}), async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    return c.json({ error: "Missing required query parameter: domain" }, 400);
  }

  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domain)) {
    return c.json({ error: "Invalid domain name" }, 400);
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json" },
    });

    if (!res.ok) {
      if (res.status === 404) {
        return c.json({ error: "Domain not found in RDAP" }, 404);
      }
      return c.json({ error: "RDAP lookup failed", status: res.status }, 502);
    }

    const data = (await res.json()) as RdapResponse;

    // Extract dates
    const dates: Record<string, string> = {};
    if (data.events) {
      for (const event of data.events) {
        dates[event.eventAction] = event.eventDate;
      }
    }

    // Extract entities (registrar, registrant, etc.)
    const contacts: Record<string, { name?: string; organization?: string }> = {};
    if (data.entities) {
      for (const entity of data.entities) {
        const role = entity.roles?.[0];
        if (!role) continue;
        const vcard = entity.vcardArray?.[1] as unknown[][] | undefined;
        if (!vcard) continue;
        contacts[role] = {
          name: extractVcardField(vcard, "fn"),
          organization: extractVcardField(vcard, "org"),
        };
      }
    }

    // Extract nameservers
    const nameservers = data.nameservers?.map((ns) => ns.ldhName) || [];

    return c.json({
      domain: data.ldhName || domain,
      status: data.status || [],
      dates,
      contacts,
      nameservers,
      dnssec: data.secureDNS?.delegationSigned ?? null,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ error: "WHOIS lookup failed", details: message }, 500);
  }
});

export default app;
