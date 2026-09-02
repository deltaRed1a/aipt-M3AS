# aipt-M3AS

**M**ulti **M**odal · **M**ulti **A**gent · **S**ecure Source Code Scanner.

M3AS accepts a **GitHub repository**, an **Azure DevOps repository** or a **ZIP upload** of a source tree,
fans the code out to a fleet of frontier models running through the **GitHub Copilot CLI**, and then
consolidates every model's security / Responsible-AI findings into one de-duplicated master report.

```
GitHub / ADO / ZIP ──▶ ingest ──▶ 8 auditor models (parallel) ──▶ consolidator (Opus 4.8, max reasoning) ──▶ master report
```

## Quick start

```bash
npm install
npm start                      # http://localhost:3000
M3AS_ENGINE=simulate npm start # offline demo mode, no Copilot CLI required
npm test
```

The Copilot engine requires the [GitHub Copilot CLI](https://github.com/github/copilot-cli) on `PATH`
(`copilot`, overridable with `M3AS_COPILOT_BIN`) and an authenticated session.

## Model fleet

The fleet is data-driven — add, remove or swap models by editing `config/models.json`
(or point `M3AS_MODELS_FILE` at your own file). No code changes are needed.

| Model | Context | Reasoning |
| --- | --- | --- |
| GPT-5.6 Sol | 1M | max |
| GPT-5.6 Terra | 1M | max |
| GPT-5.5 | 1M | max |
| Claude Opus 5 | 1M | max |
| Claude Opus 4.8 | 1M | max |
| Claude Sonnet 5 | 1M | max |
| Grok 4.6 | 425K | xhigh |
| Gemini 3.5 Flash | 1M | high |
| **Claude Opus 4.8 (consolidator)** | 1M | max |

Each entry supports `id`, `label`, `cliModel`, `contextWindow`, `reasoning`, `enabled` and `cliArgs`
(extra Copilot CLI flags), so future models drop straight in.

## How a scan runs

1. **Ingest** – repositories are shallow-cloned (`https` only, GitHub / Azure DevOps hosts only);
   ZIP uploads are extracted with Zip-Slip, symlink and zip-bomb protection.
2. **Audit** – every enabled model receives the auditor prompt in `config/auditor-prompt.md` and reviews
   the checked-out tree, returning findings as JSON in the required report format
   (finding description, steps to reproduce, severity, impact level, CVSS 3.1 vector, MITRE ATT&CK v15.1,
   MITRE ATLAS v4.7, CWE, target file/line, 3 impact bullets, insecure/secure code recommendation,
   3 mitigation bullets and reference links).
3. **Consolidate** – `config/consolidator-prompt.md` drives the long-context consolidator, which merges
   duplicates, confirms or denies single-model findings and emits the master list. If the consolidator is
   unavailable, a deterministic merge keeps the scan usable.
4. **Report** – findings are rendered in the UI and as Markdown (`workspace/<scan-id>/report.md`).

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/models` | Registry of auditor models and consolidator |
| `POST` | `/api/scans/repo` | Start a scan from `{ repoUrl, branch?, targetName?, models? }` |
| `POST` | `/api/scans/zip` | Start a scan from a multipart `archive` (.zip) upload |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/:id` | Scan status, per-model progress and findings |
| `GET` | `/api/scans/:id/events` | Server-sent progress stream |
| `GET` | `/api/scans/:id/report` | Consolidated Markdown report |

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port |
| `M3AS_ENGINE` | `copilot` | `copilot` or `simulate` (offline heuristics) |
| `M3AS_COPILOT_BIN` | `copilot` | Copilot CLI binary |
| `M3AS_MODELS_FILE` | `config/models.json` | Model registry location |
| `M3AS_WORKSPACE` | `./workspace` | Where sources and reports are stored |
| `M3AS_CONCURRENCY` | `4` | Models audited in parallel |
| `M3AS_MODEL_TIMEOUT_MS` | `1200000` | Per-model timeout |
| `M3AS_MAX_UPLOAD_BYTES` | `209715200` | Max ZIP upload size |
| `M3AS_MAX_EXTRACTED_BYTES` | `1073741824` | Max extracted size (zip-bomb guard) |
| `M3AS_RATE_LIMIT` | `10` | Scan starts allowed per client IP per minute |
| `GITHUB_TOKEN` / `ADO_PAT` | – | Optional credentials for private repositories |

## Security notes

Analysed source code is untrusted input: prompts instruct every model to treat repository content as data,
never as instructions; git and Copilot processes are spawned without a shell; repository URLs are host- and
scheme-restricted; and archive extraction is bounded and traversal-proof.
