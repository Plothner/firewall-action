# Qryptera Crypto Debt Firewall — GitHub Action

Scan every PR for cryptographic debt using Semgrep rules + LLM-powered Continuous Crypto Auditor.

## Usage

```yaml
# .github/workflows/crypto-scan.yml
name: Crypto Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: qryptera/firewall-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          # Optional: api_key: ${{ secrets.QRYPTERA_API_KEY }}
```

## What it does

1. Runs Semgrep with Qryptera's 74-rule crypto ruleset (Python, Java, Go, Node.js, Rust)
2. Extracts crypto-relevant diff hunks and sends them to the Qryptera Auditor API
3. Posts a single sticky PR comment with all findings (deterministic + LLM)
4. Auto-populates a free-tier CBOM (up to 500 assets per repo)

Free tier: 100 LLM audits per month per repo. Upgrade for unlimited.
