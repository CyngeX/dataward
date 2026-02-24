import type { Page, Route } from "patchright";
import { WorkerError } from "./types.js";

/**
 * Sets up domain enforcement on a page. All navigation requests are
 * intercepted and checked against the allowed domains list.
 * Non-matching domains are aborted and a WorkerError is stored.
 *
 * Returns an object with a `getViolation()` method to check if a
 * domain violation occurred during page interactions (e.g. JS redirects).
 */
export async function setupDomainEnforcement(
  page: Page,
  allowedDomains: string[],
): Promise<DomainEnforcer> {
  const enforcer = new DomainEnforcer(allowedDomains);
  await enforcer.attach(page);
  return enforcer;
}

export class DomainEnforcer {
  private violation: WorkerError | null = null;
  private allowedDomains: Set<string>;
  private handler: ((route: Route) => Promise<void>) | null = null;

  constructor(allowedDomains: string[]) {
    this.allowedDomains = new Set(allowedDomains.map((d) => d.toLowerCase()));
  }

  /** Attach route interception to a page. Throws if already attached. */
  async attach(page: Page): Promise<void> {
    if (this.handler !== null) {
      throw new Error("DomainEnforcer already attached");
    }
    this.handler = async (route: Route) => {
      const url = route.request().url();
      let hostname: string;
      try {
        hostname = new URL(url).hostname.toLowerCase();
      } catch {
        // Malformed URLs — allow through, Rust validates at playbook load time.
        await route.continue();
        return;
      }

      // Opaque-origin URLs (data:, blob:) have empty hostname — allow through.
      // Block javascript: and file: which also have empty hostnames.
      if (hostname === "") {
        try {
          const protocol = new URL(url).protocol;
          if (protocol === "data:" || protocol === "blob:") {
            await route.continue();
            return;
          }
        } catch {
          // If URL parsing fails, fall through to block
        }
        this.violation = new WorkerError(
          "domain_violation",
          `Blocked URL with disallowed scheme: ${url.split(":")[0]}:`,
          false,
        );
        await route.abort("blockedbyclient");
        return;
      }

      // Check if this is a navigation request (document or frame)
      const resourceType = route.request().resourceType();
      const isNavigation =
        resourceType === "document" || resourceType === "frame";

      if (isNavigation && !this.isDomainAllowed(hostname)) {
        this.violation = new WorkerError(
          "domain_violation",
          `Blocked navigation to ${hostname} — not in allowed domains`,
          false,
        );
        await route.abort("blockedbyclient");
        return;
      }

      // Allow sub-resource requests (images, CSS, scripts) from any domain.
      // Only navigation requests are domain-restricted.
      await route.continue();
    };

    await page.route("**/*", this.handler);
  }

  /** Check if a domain is in the allowed list. Exact match only. */
  private isDomainAllowed(hostname: string): boolean {
    return this.allowedDomains.has(hostname);
  }

  /** Returns the violation error if one occurred, null otherwise. */
  getViolation(): WorkerError | null {
    return this.violation;
  }

  /** Reset violation state (for retry scenarios). */
  clearViolation(): void {
    this.violation = null;
  }
}
