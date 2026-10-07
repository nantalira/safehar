export interface SafeHarVendorKeyword {
  slug: string;
  keyword: string;
  vendor: string;
}

export interface SeoPagesCatalog {
  safehar_vendor_keywords: SafeHarVendorKeyword[];
}

export const SEO_PAGES_DATA: SeoPagesCatalog = {
  safehar_vendor_keywords: [
    {
      slug: "zendesk-sanitize-har-file",
      keyword: "Zendesk sanitize HAR file before upload",
      vendor: "Zendesk",
    },
    {
      slug: "salesforce-remove-tokens-har-file",
      keyword: "Salesforce support remove tokens from HAR file",
      vendor: "Salesforce",
    },
    {
      slug: "redact-authorization-header-har",
      keyword: "how to redact authorization header in HAR file",
      vendor: "Generic HTTP",
    },
    {
      slug: "cloudflare-har-sanitizer-alternative",
      keyword: "Cloudflare HAR file sanitizer alternative",
      vendor: "Cloudflare",
    },
    {
      slug: "remove-cookies-from-har-online",
      keyword: "remove cookies from HAR file online safe",
      vendor: "Generic Web",
    },
    {
      slug: "har-file-security-leak-okta-breach",
      keyword: "HAR file security leak Okta breach",
      vendor: "InfoSec",
    },
    {
      slug: "clean-sensitive-data-network-har",
      keyword: "clean sensitive data from network HAR export",
      vendor: "DevOps",
    },
    {
      slug: "datadog-support-sanitize-har",
      keyword: "Datadog support sanitize HTTP archive",
      vendor: "Datadog",
    },
    {
      slug: "har-file-contains-passwords-remove",
      keyword: "HAR file contains passwords how to remove",
      vendor: "Generic Web",
    },
    {
      slug: "open-large-har-file-browser-no-crash",
      keyword: "open large HAR file in browser without crash",
      vendor: "Browser Tools",
    },
    {
      slug: "aws-support-har-redact-credentials",
      keyword: "AWS support HAR file redact credentials",
      vendor: "AWS",
    },
    {
      slug: "atlassian-jira-sanitize-har-file",
      keyword: "Atlassian Jira support sanitize HAR file",
      vendor: "Atlassian",
    },
  ],
};
