#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { executeSubfinder } from "./tools/subfinder.js";
import { executeDnsx } from "./tools/dnsx.js";
import { executeNaabu } from "./tools/naabu.js";
import { executeHttpx } from "./tools/httpx.js";
import { executeKatana } from "./tools/katana.js";
import { executeNuclei } from "./tools/nuclei.js";
import { executeTlsx } from "./tools/tlsx.js";
import { executeShuffledns } from "./tools/shuffledns.js";
import { runBugBountyWorkflow } from "./workflows/bug-bounty.js";
import { cleanDomain, cleanList } from "./tools/runner.js";

// ProjectDiscovery MCP server — estate-hardened fork of
// intelligent-ears/pd-tools-mcp (MIT).
// Binaries resolve via PD_TOOLS_DIR (/home/toxic/.pdtm/go/bin) and
// SHUFFLEDNS_BIN (/home/toxic/go/bin/shuffledns); per-binary override
// PD_<NAME>_BIN. All spawns are absolute-path argv, no shell, with timeouts.

const server = new Server(
  {
    name: "projectdiscovery-mcp",
    version: "1.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

function toolResult(result: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

function toolError(name: string, err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text" as const, text: `Error executing ${name}: ${msg}` }],
    isError: true,
  };
}

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "subfinder",
        description: "Discover subdomains for a given domain using passive sources",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target domain (e.g., example.com)" },
            silent: { type: "boolean", description: "Show only subdomains in output" },
          },
          required: ["domain"],
        },
      },
      {
        name: "dnsx",
        description: "Resolve DNS records for domains and subdomains",
        inputSchema: {
          type: "object",
          properties: {
            domains: { type: "array", items: { type: "string" }, description: "List of domains to resolve" },
            recordType: { type: "string", description: "DNS record type (A, AAAA, CNAME, etc.)" },
            resolvers: { type: "array", items: { type: "string" }, description: "Custom DNS resolvers (e.g. 8.8.8.8)" },
          },
          required: ["domains"],
        },
      },
      {
        name: "naabu",
        description: "Fast port scanner to discover open ports on hosts",
        inputSchema: {
          type: "object",
          properties: {
            hosts: { type: "array", items: { type: "string" }, description: "List of hosts to scan" },
            ports: { type: "string", description: "Ports to scan (e.g., '80,443' or '1-1000')" },
            topPorts: { type: "number", description: "Scan top N ports (default 100, max 1000)" },
            scanType: { type: "string", description: "c = connect scan (unprivileged, default), s = SYN scan (needs root)" },
          },
          required: ["hosts"],
        },
      },
      {
        name: "httpx",
        description: "Probe HTTP/HTTPS servers and gather information",
        inputSchema: {
          type: "object",
          properties: {
            urls: { type: "array", items: { type: "string" }, description: "List of URLs or hosts to probe" },
            followRedirects: { type: "boolean", description: "Follow HTTP redirects" },
            techDetect: { type: "boolean", description: "Enable technology detection (wappalyzer)" },
          },
          required: ["urls"],
        },
      },
      {
        name: "katana",
        description: "Fast web crawler for discovering endpoints and paths",
        inputSchema: {
          type: "object",
          properties: {
            urls: { type: "array", items: { type: "string" }, description: "List of URLs to crawl" },
            depth: { type: "number", description: "Crawl depth (default: 2, max: 5)" },
            scope: { type: "string", description: "Field scope filter (e.g., dn, rdn)" },
            maxDurationSeconds: { type: "number", description: "Max crawl duration in seconds (max 600)" },
          },
          required: ["urls"],
        },
      },
      {
        name: "nuclei",
        description: "Fast vulnerability scanner using YAML-based templates",
        inputSchema: {
          type: "object",
          properties: {
            targets: { type: "array", items: { type: "string" }, description: "List of targets to scan" },
            templateIds: { type: "array", items: { type: "string" }, description: "Nuclei template IDs to run (e.g. http-missing-security-headers)" },
            severity: { type: "array", items: { type: "string" }, description: "Filter by severity (critical, high, medium, low, info)" },
          },
          required: ["targets"],
        },
      },
      {
        name: "tlsx",
        description: "Probe TLS/SSL configuration: versions, ciphers, cert expiry, self-signed, wildcard",
        inputSchema: {
          type: "object",
          properties: {
            hosts: { type: "array", items: { type: "string" }, description: "List of hosts to probe" },
            port: { type: "number", description: "TLS port (default: 443)" },
          },
          required: ["hosts"],
        },
      },
      {
        name: "shuffledns",
        description: "Active subdomain brute-forcing with a wordlist",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target domain (e.g., example.com)" },
            wordlist: { type: "string", description: "Absolute path to wordlist file on the MCP host" },
            resolvers: { type: "array", items: { type: "string" }, description: "Custom DNS resolvers" },
          },
          required: ["domain", "wordlist"],
        },
      },
      {
        name: "bug_bounty_workflow",
        description:
          "Execute complete bug bounty reconnaissance workflow: subdomain discovery, DNS resolution, port scanning, HTTP probing, crawling, and vulnerability scanning",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target domain for bug bounty reconnaissance" },
            portScan: { type: "boolean", description: "Include port scanning (default: true)" },
            crawl: { type: "boolean", description: "Include web crawling (default: true)" },
            vulnerabilityScan: { type: "boolean", description: "Include vulnerability scanning (default: true)" },
            severityFilter: { type: "array", items: { type: "string" }, description: "Nuclei severity filter (critical, high, medium, low)" },
            maxCrawlUrls: { type: "number", description: "Maximum URLs to crawl (default: 10)" },
            maxScanUrls: { type: "number", description: "Maximum URLs to scan with Nuclei (default: 20)" },
            maxTopPorts: { type: "number", description: "Maximum top ports for Naabu (default: 100)" },
            batchSize: { type: "number", description: "Batch size for DNS/HTTP requests (default: 50)" },
            delayBetweenBatches: { type: "number", description: "Delay in milliseconds between batches (default: 1000)" },
            crawlDepth: { type: "number", description: "Crawl depth for Katana (default: 2)" },
          },
          required: ["domain"],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const a = (args ?? {}) as Record<string, any>;

  try {
    switch (name) {
      case "subfinder": {
        if (typeof a.domain !== "string") throw new Error("domain must be a string");
        return toolResult(await executeSubfinder(cleanDomain(a.domain), a.silent !== false));
      }

      case "dnsx": {
        return toolResult(
          await executeDnsx(cleanList(a.domains), a.recordType, cleanList(a.resolvers))
        );
      }

      case "naabu": {
        const scanType = a.scanType === "s" ? "s" : "c";
        return toolResult(
          await executeNaabu(cleanList(a.hosts), a.ports, a.topPorts, scanType)
        );
      }

      case "httpx": {
        return toolResult(
          await executeHttpx(cleanList(a.urls), !!a.followRedirects, !!a.techDetect)
        );
      }

      case "katana": {
        return toolResult(
          await executeKatana(cleanList(a.urls), a.depth ?? 2, a.scope, a.maxDurationSeconds)
        );
      }

      case "nuclei": {
        return toolResult(
          await executeNuclei(cleanList(a.targets), a.templateIds, a.severity)
        );
      }

      case "tlsx": {
        return toolResult(await executeTlsx(cleanList(a.hosts), a.port ?? 443));
      }

      case "shuffledns": {
        if (typeof a.domain !== "string" || typeof a.wordlist !== "string") {
          throw new Error("domain and wordlist must be strings");
        }
        return toolResult(
          await executeShuffledns(cleanDomain(a.domain), a.wordlist, cleanList(a.resolvers))
        );
      }

      case "bug_bounty_workflow": {
        if (typeof a.domain !== "string") throw new Error("domain must be a string");
        return toolResult(
          await runBugBountyWorkflow(cleanDomain(a.domain), {
            portScan: a.portScan ?? true,
            crawl: a.crawl ?? true,
            vulnerabilityScan: a.vulnerabilityScan ?? true,
            severityFilter: a.severityFilter,
            rateLimit: {
              maxCrawlUrls: a.maxCrawlUrls,
              maxScanUrls: a.maxScanUrls,
              maxTopPorts: a.maxTopPorts,
              batchSize: a.batchSize,
              delayBetweenBatches: a.delayBetweenBatches,
              crawlDepth: a.crawlDepth,
            },
          })
        );
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return toolError(name, error);
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ProjectDiscovery MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
