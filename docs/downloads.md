# Optional Cloudflare download redirect

GitHub Releases is the canonical download source. A branded URL can redirect to its release assets without proxying binary downloads through the gateway VM.

1. Add a proxied CNAME: `download-proxy` -> `api-proxy.dinmoo.com`.
2. In Cloudflare Rules -> Redirect Rules, create a Single Redirect matching `http.host eq "download-proxy.dinmoo.com"`.
3. Use a dynamic target expression:

```
concat("https://github.com/igoroalonge/dinmoo-proxy/releases/latest/download", http.request.uri.path)
```

Use status 302 and disable query string preservation. This maps `/install.sh`, `/install.ps1`, `/latest.json`, and `/dinmoo-proxy-windows-x86_64.exe` to the corresponding latest-release asset. A bare `/` does not select an OS-specific binary; use the installer paths or add a higher-priority root redirect to `https://github.com/igoroalonge/dinmoo-proxy/releases/latest`.

Keep `api-proxy.dinmoo.com` DNS only. Only the branded HTTP download hostname should be orange-cloud proxied.

References: [Cloudflare dynamic redirects](https://developers.cloudflare.com/rules/url-forwarding/single-redirects/settings/) and [GitHub latest release asset links](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases).
