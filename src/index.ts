import { Hono } from "hono";
import { cdpPaymentMiddleware } from "x402-cdp";
import { extractParams } from "x402-ai";
import { openapiFromMiddleware } from "x402-openapi";

const app = new Hono<{ Bindings: Env }>();

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

const SYSTEM_PROMPT = `You are a parameter extractor for a DNS lookup and WHOIS service.
Extract the following from the user's message and return JSON:
- "domain": the domain name to look up (required)
- "type": specific DNS record type: A, AAAA, MX, TXT, NS, CNAME, or SOA. Omit for all types. (optional)
- "action": either "dns" (DNS record lookup) or "whois" (WHOIS/RDAP registration info). Default "dns". (optional)

If the user mentions WHOIS, registration, registrar, or ownership info, set action to "whois".
Otherwise default to "dns".

Return ONLY valid JSON, no explanation.
Examples:
- {"domain": "example.com"}
- {"domain": "example.com", "type": "MX"}
- {"domain": "example.com", "action": "whois"}`;

const ROUTES = {
  "POST /": {
    accepts: [{ scheme: "exact", price: "$0.005", network: "eip155:8453", payTo: "0x0" as `0x${string}` }],
    description: "Look up DNS records or WHOIS registration info for a domain. Send {\"input\": \"your request\"}",
    mimeType: "application/json",
    extensions: {
      bazaar: {
        info: {
          input: {
            type: "http",
            method: "POST",
            bodyType: "json",
            body: {
              input: { type: "string", description: "Describe the DNS lookup or WHOIS query you want to perform", required: true },
            },
          },
          output: { type: "json" },
        },
        schema: {
          properties: {
            input: {
              properties: { method: { type: "string", enum: ["POST"] } },
              required: ["method"],
            },
          },
        },
      },
    },
  },
};

app.use(
  cdpPaymentMiddleware((env) => ({
    "POST /": { ...ROUTES["POST /"], accepts: [{ ...ROUTES["POST /"].accepts[0], payTo: env.SERVER_ADDRESS as `0x${string}` }] },
  }))
);

app.post("/", async (c) => {
  const body = await c.req.json<{ input?: string }>();
  if (!body?.input) {
    return c.json({ error: "Missing 'input' field" }, 400);
  }

  const params = await extractParams(c.env.CF_GATEWAY_TOKEN, SYSTEM_PROMPT, body.input);
  const domain = params.domain as string;
  if (!domain) {
    return c.json({ error: "Could not determine domain to look up" }, 400);
  }

  // Basic domain validation
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domain)) {
    return c.json({ error: "Invalid domain name" }, 400);
  }

  const action = ((params.action as string) || "dns").toLowerCase();

  if (action === "whois") {
    // --- WHOIS/RDAP lookup ---
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
  }

  // --- DNS lookup (default) ---
  const requestedType = (params.type as string)?.toUpperCase();
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

app.get("/.well-known/openapi.json", openapiFromMiddleware("x402 DNS Lookup", "dns.camelai.io", ROUTES));

app.get("/", (c) => {
  return c.json({
    service: "x402-dns-lookup",
    description: "Look up DNS records and WHOIS registration info for domains. Send POST / with {\"input\": \"DNS records for example.com\"}",
    price: "$0.005 per request (Base mainnet)",
  });
});

export default app;
