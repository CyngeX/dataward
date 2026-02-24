import { describe, it, expect, vi } from "vitest";
import { DomainEnforcer } from "../domain.js";
import { WorkerError } from "../types.js";

// --- Mock helpers ---

interface MockRoute {
  request: () => { url: () => string; resourceType: () => string };
  continue: ReturnType<typeof vi.fn>;
  abort: ReturnType<typeof vi.fn>;
}

function createMockRoute(
  url: string,
  resourceType: string = "document",
): MockRoute {
  return {
    request: () => ({
      url: () => url,
      resourceType: () => resourceType,
    }),
    continue: vi.fn().mockResolvedValue(undefined),
    abort: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockPage() {
  let routeHandler: ((route: MockRoute) => Promise<void>) | null = null;

  return {
    route: vi.fn((pattern: string, handler: (route: MockRoute) => Promise<void>) => {
      routeHandler = handler;
    }),
    // Test helper: simulate a request through the route handler
    async simulateRequest(route: MockRoute) {
      if (!routeHandler) throw new Error("No route handler attached");
      await routeHandler(route);
    },
  };
}

// --- Tests ---

describe("DomainEnforcer", () => {
  it("allows navigation to an allowed domain", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://spokeo.com/optout");
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(route.abort).not.toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("blocks navigation to a non-allowed domain", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://evil.com/phish");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(route.continue).not.toHaveBeenCalled();

    const violation = enforcer.getViolation();
    expect(violation).toBeInstanceOf(WorkerError);
    expect(violation!.code).toBe("domain_violation");
    expect(violation!.message).toContain("evil.com");
  });

  it("requires exact domain match — www.spokeo.com != spokeo.com", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://www.spokeo.com/optout");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(enforcer.getViolation()).not.toBeNull();
  });

  it("allows www.spokeo.com when explicitly listed", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com", "www.spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://www.spokeo.com/optout");
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("allows sub-resource requests from any domain", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    // Image from CDN — should be allowed even though cdn.example.com is not in allowed list
    const route = createMockRoute("https://cdn.example.com/logo.png", "image");
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(route.abort).not.toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("allows script sub-resources from any domain", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute(
      "https://analytics.example.com/script.js",
      "script",
    );
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("blocks frame navigation to non-allowed domain", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://iframe-ad.com/ad", "frame");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(enforcer.getViolation()).not.toBeNull();
  });

  it("allows data: URLs through", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("data:text/html,<h1>hello</h1>");
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("blocks javascript: URLs", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("javascript:alert(1)");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(enforcer.getViolation()).not.toBeNull();
    expect(enforcer.getViolation()!.code).toBe("domain_violation");
  });

  it("blocks file: URLs", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("file:///etc/passwd");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(enforcer.getViolation()).not.toBeNull();
  });

  it("is case-insensitive for domain matching", async () => {
    const enforcer = new DomainEnforcer(["Spokeo.COM"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://spokeo.com/optout");
    await page.simulateRequest(route);

    expect(route.continue).toHaveBeenCalled();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("clearViolation resets the violation state", async () => {
    const enforcer = new DomainEnforcer(["spokeo.com"]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://evil.com/phish");
    await page.simulateRequest(route);
    expect(enforcer.getViolation()).not.toBeNull();

    enforcer.clearViolation();
    expect(enforcer.getViolation()).toBeNull();
  });

  it("handles empty allowed domains list — blocks everything", async () => {
    const enforcer = new DomainEnforcer([]);
    const page = createMockPage();
    await enforcer.attach(page as any);

    const route = createMockRoute("https://any-domain.com/page");
    await page.simulateRequest(route);

    expect(route.abort).toHaveBeenCalledWith("blockedbyclient");
    expect(enforcer.getViolation()).not.toBeNull();
  });
});
