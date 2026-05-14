# NGINX Rift 配置扫描器

这是一个用于检查 NGINX 配置是否存在 CVE-2026-42945（NGINX Rift）风险模式的轻量级脚本。

该漏洞由 depthfirst 在文章 [NGINX Rift: Achieving NGINX RCE via an 18-Year-Old Vulnerability](https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability) 中披露。根据文章和 F5/NVD 描述，风险与 `ngx_http_rewrite_module` 的特定配置组合有关：在同一配置上下文中，`rewrite` 的替换字符串包含 `?`，后续 `rewrite`、`if` 或 `set` 又引用了未命名 PCRE 捕获变量，例如 `$1`、`$2`。

## 检查目标

本工具主要检查 NGINX 配置文件中是否存在类似下面的高风险序列：

```nginx
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;
}
```

风险点不是单独的 `rewrite` 或 `set`，而是它们在同一上下文中的执行顺序：

1. `rewrite` 使用正则捕获，并且替换字符串包含 `?`
2. 后续 `rewrite`、`if` 或 `set` 使用 `$1`、`$2` 等未命名捕获变量

这种组合可能触发 NGINX 脚本引擎长度计算和实际拷贝阶段的状态不一致，导致堆缓冲区溢出。

## 影响范围

depthfirst 文章列出的受影响范围包括：

- NGINX Open Source 0.6.27 到 1.30.0
- NGINX Plus R32 到 R36
- 部分基于 NGINX 的 F5 / NGINX 产品

实际修复版本和产品矩阵请以 F5 官方公告或发行版安全公告为准。即使版本处于受影响范围内，也通常还需要存在特定 `rewrite` 配置序列才会触发该漏洞。

脚本会同时输出当前 NGINX 版本和配置扫描结果：

- 版本在 `0.6.27 - 1.30.0` 且配置命中风险序列：必须升级 NGINX 或调整配置。
- 版本在 `0.6.27 - 1.30.0` 但配置未命中风险序列：建议升级，但本工具未发现配置触发条件。
- 配置命中风险序列但版本不在受影响范围：建议复核配置并保持已修复版本。

## 使用方法

直接扫描当前机器的完整 NGINX 配置：

```bash
python3 scan_rift.py
```

脚本会执行：

```bash
nginx -T
```

如果当前用户没有权限读取完整配置，请使用 `sudo`：

```bash
sudo python3 scan_rift.py
```

也可以扫描一个已经导出的配置文件：

```bash
python3 scan_rift.py /path/to/nginx-full.conf
```

例如先导出配置再扫描：

```bash
sudo nginx -T > nginx-full.conf
python3 scan_rift.py nginx-full.conf
```

## 输出说明

未发现风险序列时：

```text
--- NGINX Rift Config Scanner (CVE-2026-42945) ---
Current NGINX Version: nginx version: nginx/1.23.3
Version Status: Affected version range for NGINX Open Source (0.6.27 - 1.30.0)

[+] No vulnerable CVE-2026-42945 sequences detected.

[Recommendation]: Current NGINX version is in the affected range, but no vulnerable config sequence was detected. Upgrade is recommended, but config risk was not found by this scanner.
```

发现可疑序列时：

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

发现命中后应人工确认该配置上下文是否可被外部请求触达，并尽快升级 NGINX 或调整配置。

## 处置建议

- 升级到供应商发布的修复版本。
- 检查所有 `location`、`server`、`if` 等上下文中的 `rewrite` / `set` 组合。
- 避免在带 `?` 的 `rewrite` 后继续使用 `$1`、`$2` 等未命名捕获变量。
- 可以改用命名捕获、提前保存变量、拆分处理逻辑，或移除不必要的 query string rewrite。
- 在修复前，优先处理公网可访问的 NGINX 服务和反向代理入口。
- 不要只依赖版本判断，配置是否包含触发序列同样关键。

## 限制

该脚本是配置静态扫描工具，目标是快速发现高风险模式，不等同于漏洞利用验证。

- 可能存在误报，需要结合实际 NGINX 上下文人工复核。
- 复杂的多行指令、include 展开异常或动态生成配置可能影响扫描效果。
- 扫描不到风险不代表绝对安全，仍应升级到官方修复版本。

## 参考

- depthfirst: <https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability>
- NVD CVE-2026-42945: <https://nvd.nist.gov/vuln/detail/CVE-2026-42945>
- F5 Advisory K000161019: <https://my.f5.com/manage/s/article/K000161019>
