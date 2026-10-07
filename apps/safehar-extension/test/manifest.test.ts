import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";

describe("SafeHAR Chrome Extension Packaging (Task 4.1 & 4.2)", () => {
  const extensionDir = path.resolve(__dirname, "..");
  const manifestPath = path.join(extensionDir, "manifest.json");

  test("Task 4.1: manifest.json conforms to Manifest V3 with Zero Host Permissions", () => {
    expect(fs.existsSync(manifestPath)).toBe(true);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

    // Manifest V3 verification
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toContain("SafeHAR");
    expect(manifest.version).toBe("0.1.0");

    // Strictly lowest privileges: only "storage"
    expect(manifest.permissions).toEqual(["storage"]);

    // Zero Host Permissions verification
    expect(manifest.host_permissions).toBeUndefined();
    expect(JSON.stringify(manifest)).not.toContain("<all_urls>");
    expect(JSON.stringify(manifest)).not.toContain("*://*/*");

    // Action & CSP
    expect(manifest.action.default_popup).toBe("popup.html");
    expect(manifest.content_security_policy.extension_pages).toContain("script-src 'self'");
  });

  test("Task 4.2: Extension artifacts exist and are ready for 'Load unpacked'", () => {
    const popupHtml = path.join(extensionDir, "popup.html");
    const popupJs = path.join(extensionDir, "popup.js");

    expect(fs.existsSync(popupHtml)).toBe(true);
    expect(fs.existsSync(popupJs)).toBe(true);

    const htmlContent = fs.readFileSync(popupHtml, "utf-8");
    expect(htmlContent).toContain("popup.js");
    expect(htmlContent).toContain("toggle-auth");
    expect(htmlContent).toContain("toggle-stripe");
    expect(htmlContent).toContain("drop-zone");

    const jsContent = fs.readFileSync(popupJs, "utf-8");
    // Verify storage persistence logic is bundled
    expect(jsContent).toContain("safehar_user_redaction_options");
    expect(jsContent).toContain("[REDACTED_STRIPE_SECRET_KEY]");
  });
});
