# NGINX Rift Config Scanner

Language: [中文](README.md) | English

This is a lightweight scanner for checking whether an NGINX configuration contains the risky CVE-2026-42945, also known as NGINX Rift, configuration pattern.

The issue was disclosed by depthfirst in [NGINX Rift: Achieving NGINX RCE via an 18-Year-Old Vulnerability](https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability). Based on the article and F5/NVD descriptions, the risk depends on a specific `ngx_http_rewrite_module` configuration sequence: in the same configuration context, a `rewrite` replacement contains `?`, and a following `rewrite`, `if`, or `set` references unnamed PCRE captures such as `$1` or `$2`.

## What It Checks

This tool looks for high-risk sequences like:

```nginx
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;
}
```

The risk is not a standalone `rewrite` or `set` directive. The risky condition is the execution order inside the same context:

1. `rewrite` uses a regex capture and its replacement contains `?`
2. A following `rewrite`, `if`, or `set` uses unnamed capture variables such as `$1` or `$2`

This combination can cause inconsistent state between NGINX script length calculation and the actual copy phase, potentially leading to a heap buffer overflow.

## Affected Range

The depthfirst article lists the affected range as:

- NGINX Open Source 0.6.27 through 1.30.0
- NGINX Plus R32 through R36
- Some F5 / NGINX products based on NGINX

Use the official F5 advisory or your distribution security advisory as the source of truth for fixed versions and product-specific impact. Even when the version is in the affected range, the vulnerable configuration sequence is typically also required to trigger the issue.

The script prints both the current NGINX version and the configuration scan result:

- Version is in `0.6.27 - 1.30.0` and vulnerable config is found: upgrade NGINX or adjust the config.
- Version is in `0.6.27 - 1.30.0` but vulnerable config is not found: upgrade is recommended, but this scanner did not find the triggering config pattern.
- Vulnerable config is found but the version is outside the affected range: review the config and keep the fixed version.

## Usage

Scan the full NGINX configuration on the current host:

```bash
python3 scan_rift.py
```

The script runs:

```bash
nginx -T
```

If the current user cannot read the full configuration, run it with `sudo`:

```bash
sudo python3 scan_rift.py
```

You can also scan an exported configuration file:

```bash
python3 scan_rift.py /path/to/nginx-full.conf
```

For example:

```bash
sudo nginx -T > nginx-full.conf
python3 scan_rift.py nginx-full.conf
```

## Output

When no vulnerable sequence is found:

```text
--- NGINX Rift Config Scanner (CVE-2026-42945) ---
Current NGINX Version: nginx version: nginx/1.23.3
Version Status: Affected version range for NGINX Open Source (0.6.27 - 1.30.0)

[+] No vulnerable CVE-2026-42945 sequences detected.

[Recommendation]: Current NGINX version is in the affected range, but no vulnerable config sequence was detected. Upgrade is recommended, but config risk was not found by this scanner.
```

When a suspicious sequence is found:

```text
--- NGINX Rift Config Scanner (CVE-2026-42945) ---
Current NGINX Version: nginx version: nginx/1.23.3
Version Status: Affected version range for NGINX Open Source (0.6.27 - 1.30.0)

[!] VULNERABLE SEQUENCE FOUND:
    Context: location ~ ^/api/(.*)$ {
    [1. Rewrite With ?] rewrite ^/api/(.*)$ /internal?migrated=true;
    [2. Follow-up $N]   set $original_endpoint $1;

[Action Required]: Current NGINX version is affected and vulnerable config was found. Upgrade NGINX or adjust the reported rewrite/if/set sequence.
```

If the scanner reports a match, manually verify whether that configuration context is reachable by external requests, then upgrade NGINX or adjust the configuration.

## Remediation

- Upgrade to a vendor-provided fixed version.
- Review `rewrite` / `set` combinations in `location`, `server`, `if`, and related contexts.
- Avoid using unnamed capture variables such as `$1` or `$2` after a `rewrite` that contains `?`.
- Consider named captures, saving variables before rewrite logic, splitting rewrite handling, or removing unnecessary query-string rewrites.
- Prioritize internet-facing NGINX reverse proxies and entry points.
- Do not rely on version checks alone; the triggering configuration sequence is also important.

## Limitations

This is a static configuration scanner intended to quickly identify high-risk patterns. It is not an exploit validator.

- False positives are possible and should be manually reviewed.
- Complex multi-line directives, unusual `include` expansion, or dynamically generated configuration may affect scan quality.
- A clean result from this scanner does not guarantee complete safety. Upgrading to the official fixed version is still recommended.

## References

- depthfirst: <https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability>
- NVD CVE-2026-42945: <https://nvd.nist.gov/vuln/detail/CVE-2026-42945>
- F5 Advisory K000161019: <https://my.f5.com/manage/s/article/K000161019>
