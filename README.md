# HoneyPrompt.ai

**Zero-Trust Context Security for AI Agents.**

Deep-tech cybersecurity for agent runtimes: inject semantic decoys (honeypots) into the context window; if an agent accesses or leaks a decoy, trigger a **Semantic Kill-Switch** and emit a **cryptographically signed execution receipt**.

## Brand

- Dark mode default: Obsidian black / dark slate
- Accents: Neon Yellow / Honey (alerts & honey-traps)
- Vibe: clean, minimal, high-end enterprise SOC

## Why

Agent-to-agent cascades (memory poisoning, prompt injection) can exfiltrate secrets through the context window. HoneyPrompt turns the context into a tripwire: decoys look real to an abuser, but any leak is blocked and attested.

## Stack

| Layer | Tech |
|-------|------|
| SDK / core | Python (`honeyprompts`) wrapping OpenAI / LangChain-style calls |
| Dashboard | React, Vite, Tailwind CSS |
| Backend / DB | Supabase (Auth, Postgres, RLS) |
| Frontend host | Vercel |
| SIEM / EDR | CEF webhooks (SentinelOne, Zscaler, …) |

## Phases (Jerry gates each step)

1. **Python SDK** — Decoy Registry, Injector, Interceptor (kill-switch), HMAC-SHA256 receipts  
2. **Supabase schema** — `agents`, `decoy_templates`, `execution_receipts` + RLS  
3. **SOC Dashboard** — metrics, live receipts table, drill-down modal  
4. **EDR/SIEM webhook** — Vercel serverless → CEF

## Repo layout

```
honeyprompts/   # Phase 1 Python package
supabase/       # SQL init + RLS
dashboard/      # React + Vite + Tailwind
api/            # Vercel webhook (CEF)
docs/           # Design notes
```

## Security notes

- Decys are synthetic (e.g. `AKIA-HONEY-…`); never store real production secrets as decoys.
- Receipts are HMAC-SHA256 signed; treat the signing key as a secret.
- No auto-exploit, no unlawful access. This is defensive tooling only.

## Status

Greenfield. Owned by the **HoneyPrompt** agent room (Rhea Vale lead).

Repo: https://github.com/Senior3514/HoneyPrompt
