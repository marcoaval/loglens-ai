# LogLens AI

**AI-powered security log analyzer.** LogLens AI reads exported Windows or macOS security/event logs, sends them in
batches to a Qwen Coder large language model (hosted on the UTSA Compute Hub GPUStack), and classifies every entry as
**BENIGN**, **SUSPICIOUS**, or **MALICIOUS** with a one-sentence explanation. It then produces a Markdown security
assessment report with a risk rating, findings, and recommendations.

## Features
- Loads CSV exports (Event Viewer / PowerShell `Export-Csv`) and plain-text logs (macOS `log show`)
- Batched LLM classification with a SOC-analyst system prompt and strict JSON output
- Validates every label and retries missed entries individually; anything unparseable is conservatively marked SUSPICIOUS for manual review
- Confirms every MALICIOUS label with a second single-entry review before it affects the risk rating
- Redacts SIDs, account names, user-profile paths, e-mail and IP addresses before writing the report
- Overall risk rating plus AI-generated remediation recommendations

## Files
| File | Purpose |
|---|---|
| `LogLens_AI.ipynb` | The tool (connection, design session with Qwen Coder, analyzer code, report generation) |
| `security_assessment_report.md` | Report generated from a real Windows event log export |

## Usage
1. Connect to the UTSA network or VPN.
2. Open `LogLens_AI.ipynb` in Jupyter and set the `GPUSTACK_API_KEY` environment variable or enter the key at the hidden prompt; it is never saved.
3. Export a log (commands are in the notebook), upload it next to the notebook, set `LOG_PATH`, and run all cells.

## Security
- The API key is never stored in the notebook or repository.
- Raw logs are excluded via `.gitignore`; only the redacted report is published.
- AI classifications are a triage aid, not a verdict; findings should be verified before acting on them.

## Tech
Python · OpenAI-compatible client · GPUStack · Qwen Coder · Jupyter
