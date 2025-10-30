# HTTPS-Only/Upgrade Browser Extension & Config

## Purpose
This extension and config ensure:
- All browser traffic for non-local sites is upgraded to HTTPS.
- Silent fallback to HTTP/downgrade is blocked.
- User is notified when insecure HTTP is attempted on a domain with known HTTPS support.

## Recommended Tools
- Use [HTTPS Everywhere](https://www.eff.org/https-everywhere) (deprecated but forkable; classic reference code)
- For **Firefox**: enable built-in HTTPS-Only mode (about:preferences#privacy → HTTPS-Only Mode)
- For **Chrome**: enable 'Always use secure connections' (chrome://settings/security)

## Write-Your-Own Extension
A basic extension manifest for Chromium-based browsers:
```json
{
  "manifest_version": 2,
  "name": "HTTPS Latch",
  "version": "1.0",
  "background": { "scripts": ["background.js"] },
  "permissions": [ "webRequest", "webRequestBlocking", "*://*/*" ]
}
```

background.js content:
```javascript
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    if (details.url.startsWith("http://")) {
      var upgrade = details.url.replace("http://", "https://");
      return {redirectUrl: upgrade};
    }
  },
  {urls: ["<all_urls>"]},
  ["blocking"]
);
```

## Server-side (for developers)
- Enable [HSTS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security):
  - For Apache:
    ```
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    ```
  - For Nginx:
    ```
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    ```
- Use CSP to block mixed content if you write your own site:
  - Example: `Content-Security-Policy: upgrade-insecure-requests`

## Summary
- On Firefox: turn on HTTPS-Only Mode.
- On Chrome/Edge: turn on 'Always use secure connections,' use extension above, or fork HTTPS Everywhere.
- For all web devs: enable HSTS and CSP headers by default for your domain.
