# VSXSentry Project

[github.com/vsxsentry](https://github.com/vsxsentry)

# VSXSentry feed builder

## What it does

It builds the VSXSentry feed from two sources:

1. **Microsoft's `RemovedPackages.md`** — official list of extensions removed from the VS Marketplace with removal reasons (Malware, Typo-squatting, Impersonation, Spam, etc.)
2. **My local manually filled CSV** (`vscode_extensions_static.csv`) with the following headers:

```csv
extension_id,metadata_comment,metadata_severity,metadata_category,metadata_reference
```

The static CSV contains both **malicious** extensions (manually curated threat intel) and **risky** extensions (legitimate but dual-use tools that represent enterprise risk). The two types are distinguished by category prefix:

- Malicious categories: `malware`, `typo-squatting`, `impersonation`, `spam`, `potentially-malicious`, ...
- Risky categories: `risky-remote-access`, `risky-tunnel`, `risky-credential-access`, `risky-ai-code-access`, `risky-database-access`, `risky-cloud-access`, `risky-file-transfer`, `risky-code-execution`, `risky-api-client`, `risky-collaboration`, `risky-infrastructure`, `risky-git-access`

## Outputs

The script writes these files under `feeds/`:

### Combined feed (malicious + risky)
| File | Description |
|---|---|
| `vsxsentry_feed.csv` | Full merged feed — all records |
| `vsxsentry_feed.json` | Full merged feed as JSON (`feed_type: "all"`) |
| `stats.json` | Aggregated statistics with malicious/risky breakdown |

### Malicious only (categories without `risky-` prefix)
| File | Description |
|---|---|
| `vsxsentry_malicious_feed.csv` | Malicious extensions only |
| `vsxsentry_malicious_feed.json` | Malicious extensions as JSON (`feed_type: "malicious"`) |
| `ioc_all_extension_ids.txt` | All malicious extension IDs (one per line) |
| `ioc_high_risk_extension_ids.txt` | High/critical severity malicious IDs only |
| `ioc_block_publishers.txt` | Publishers with high/critical malicious extensions |

### Risky only (categories with `risky-` prefix)
| File | Description |
|---|---|
| `vsxsentry_risky_feed.csv` | Risky extensions only |
| `vsxsentry_risky_feed.json` | Risky extensions as JSON (`feed_type: "risky"`) |
| `risky_extension_ids.txt` | All risky extension IDs (one per line) |

> **Note:** IOC blocklists (`ioc_*`) contain only malicious extensions. Risky extensions are legitimate tools — they get their own separate feed for enterprise visibility and policy decisions, not for blocking.

## Usage

```bash
python3 build_vscode_extensions_feed.py
```

Or with explicit paths:

```bash
python3 build_vscode_extensions_feed.py \
  --static-csv vscode_extensions_static.csv \
  --output-dir feeds
```

### Arguments

| Flag | Default | Description |
|---|---|---|
| `--removed-url` | GitHub raw URL | URL for Microsoft's `RemovedPackages.md` |
| `--reference-url` | GitHub blob URL | Reference URL stored in feed records |
| `--static-csv` | `vscode_extensions_static.csv` | Path to analyst-curated static CSV |
| `--output-dir` | `feeds` | Output directory |

## How the merge works

1. **Microsoft `RemovedPackages.md`** is parsed first (markdown table or loose-line fallback).
2. **Static CSV** entries are merged on top:
   - If an `extension_id` already exists from Microsoft, the static CSV values **override** severity, category, and comment (analyst curation takes precedence).
   - If an `extension_id` is new (not in Microsoft's list), it's added as a `static_list` entry.
   - The `metadata_reference` column from the static CSV is preserved when present.
3. The merged result is sorted by severity (critical first), then category, then extension ID.
4. The split into malicious vs risky is based on whether `metadata_category` starts with `risky-`.

## Severity mapping for Microsoft's removed reasons

| Microsoft Reason | Severity | Category |
|---|---|---|
| Malware | `critical` | `malware` |
| Potentially malicious | `high` | `potentially-malicious` |
| Typo-squatting | `high` | `typo-squatting` |
| Impersonation | `high` | `impersonation` |
| Spam | `medium` | `spam` |
| Untrustworthy | `medium` | `untrustworthy` |
| Copyright violation | `low` | `copyright-violation` |

## Risky extension categories

These are legitimate extensions that represent enterprise risk - not malicious, but dual-use:

| Category | Examples |
|---|---|
| `risky-remote-access` | Remote SSH, Remote Tunnels, RDP, Codespaces, Gitpod |
| `risky-tunnel` | ngrok, Cloudflare Tunnel, Tailscale, LocalTunnel |
| `risky-credential-access` | 1Password, Keeper Security, HashiCorp Vault, Doppler |
| `risky-ai-code-access` | Copilot, Cline, Roo Code, Continue, Tabnine, Codeium |
| `risky-cloud-access` | AWS Toolkit, Azure Resources, Cloud Code, Kubernetes |
| `risky-database-access` | SQLTools, Database Client, MongoDB, Redis, MSSQL |
| `risky-file-transfer` | SFTP sync, FTP-simple, Deploy Reloaded, PRO Deployer |
| `risky-code-execution` | Code Runner, Jupyter, PowerShell, Live Server |
| `risky-api-client` | Thunder Client, Postman, REST Client |
| `risky-collaboration` | Live Share |
| `risky-infrastructure` | Terraform, Pulumi, Tilt |
| `risky-git-access` | GitLens, GitHub Pull Requests |

and more ...

## Site

The VSXSentry site at [vsxsentry.github.io](https://vsxsentry.github.io) fetches the combined `vsxsentry_feed.json` and generates all export formats client-side (Splunk, Sentinel, Sigma, STIX2, MISP, YARA, Suricata, OpenIOC, Elastic, OpenCTI, and more). The site lets users filter malicious vs risky entries using the category filter.
