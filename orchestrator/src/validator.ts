import { readJsonFile, resolveProjectPath } from "./utils";
import type { MarketRequestInput } from "./types";

interface AllowlistConfig {
  allowedDomains: string[];
}

export class ValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super("Request validation failed");
    this.issues = issues;
  }
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase();
}

function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  const normalizedHost = normalizeDomain(hostname);

  return allowedDomains.some((domain) => {
    const normalizedDomain = normalizeDomain(domain);
    return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
  });
}

function isAddress(value: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(value);
}

function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

export async function loadAllowlistDomains(): Promise<string[]> {
  const configPath = resolveProjectPath("config", "source-allowlist.json");
  const config = await readJsonFile<AllowlistConfig>(configPath, { allowedDomains: [] });
  return config.allowedDomains.map(normalizeDomain);
}

export async function validateMarketRequest(input: MarketRequestInput): Promise<MarketRequestInput> {
  const issues: string[] = [];

  const question = input.question?.trim();
  const description = input.description?.trim();
  const resolutionCriteria = input.resolutionCriteria?.trim();
  const submitterAddress = input.submitterAddress?.trim();
  const sourceUrls = (input.sourceUrls ?? []).map((value) => value.trim()).filter(Boolean);

  if (!question) {
    issues.push("question is required");
  }
  if (!description) {
    issues.push("description is required");
  }
  if (!resolutionCriteria) {
    issues.push("resolutionCriteria is required");
  }
  if (!submitterAddress || !isAddress(submitterAddress)) {
    issues.push("submitterAddress must be a valid EVM address");
  }
  if (sourceUrls.length === 0) {
    issues.push("sourceUrls must contain at least one url");
  }

  const allowlist = await loadAllowlistDomains();

  sourceUrls.forEach((url) => {
    if (!isHttpUrl(url)) {
      issues.push(`invalid url format: ${url}`);
      return;
    }

    const parsed = new URL(url);
    if (!isDomainAllowed(parsed.hostname, allowlist)) {
      issues.push(`source domain not allowed: ${parsed.hostname}`);
    }
  });

  if (issues.length > 0) {
    throw new ValidationError(issues);
  }

  return {
    question: question!,
    description: description!,
    sourceUrls: Array.from(new Set(sourceUrls)),
    resolutionCriteria: resolutionCriteria!,
    submitterAddress: submitterAddress!
  };
}
