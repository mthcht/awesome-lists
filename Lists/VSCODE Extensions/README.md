# VSXSentry feed builder

## What it does

It builds the VSXSentry feed from two sources:

1. Microsoft's `RemovedPackages.md`
2. Your local analyst-curated CSV with the following headers:

```csv
extension_id,metadata_comment,metadata_severity,metadata_category
```

## Outputs

The script writes these files under `feeds/`:

- `vsxsentry_feed.csv`
- `vsxsentry_feed.json`
- `ioc_all_extension_ids.txt`
- `ioc_high_risk_extension_ids.txt`
- `ioc_block_publishers.txt`
- `stats.json`

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

## Notes

- Microsoft feed parsing supports both markdown-table format and loose line format as a fallback.
- Static CSV values override Microsoft-derived severity/category/comment for duplicate `extension_id` values.
- The feed is designed for GitHub Pages consumption and for downstream SIEM / inventory use.

## Severity mapping for Microsoft's removed reasons

- `Malware` -> `critical`
- `Potentially malicious` -> `high`
- `Typo-squatting` -> `high`
- `Impersonation` -> `high`
- `Spam` -> `medium`
- `Untrustworthy` -> `medium`
- `Copyright violation` -> `low`

## Site

Check out the site https://vsxsentry.github.io 
