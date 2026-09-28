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
honeyprompts/   # Phase 1 Python package (present)
examples/       # Phase 1 offline example (present)
tests/          # Phase 1 pytest suite (present)
supabase/       # Phase 2 — not present yet
dashboard/      # Phase 3 — not present yet
api/            # Phase 4 — not present yet
docs/           # not present yet
```

## Phase 1 SDK

Package `honeyprompts` (Python 3.10+). Phase 1 wraps OpenAI-style `chat.completions.create` only. There is no LangChain adapter in this phase. Streamed completions are rejected (`stream=True`): a chunked response is not scanned, so it is not passed through.

Detection is an exact substring match of a registered synthetic secret on the paths below. It is not a semantic classifier. A leak that never repeats the secret value is not detected.

### Install and test

```bash
pip install -e ".[dev]"
pytest
python examples/phase1_flow.py
```

The example stubs `chat.completions.create`. Tests and the example do not call the network and do not need an API key.

### Components

- `DecoyRegistry.mint` — mint a synthetic decoy. There is no parameter for a caller-supplied secret.
- `DecoyRegistry.register` — reload a value that already matches a synthetic pattern, for a future store to round-trip. Any other value is refused. The refused value is not copied into the error.
- `Injector.inject_messages` — copy the message list and plant missing decoys in a system message as environment-style assignments (`AWS_ACCESS_KEY_ID=AKIA-HONEY-…`). User messages are not rewritten. A second inject does not stack another copy of a value that is already present. `placement` other than `"system"` is rejected. `decoy_ids=None` plants every registered decoy; an empty list plants nothing.
- `protect` — return a wrapper (the original client is not modified) whose `chat.completions.create` scans prior assistant/tool/function messages, injects decoys, calls the inner client, then scans the response. `messages` is a keyword argument.
- `Interceptor` — on a match, raise `HoneyTrapTriggeredException` and do not return the leaking response. The exception's `receipt` is signed. The exception text and the receipt do not include the secret value.
- `verify_receipt` — check an HMAC-SHA256 receipt. `ReceiptSigner` issues one.

Other methods on the client are left untouched and are not scanned.

Signing key: constructor argument `signing_key`, or environment variable `HONEYPROMPTS_SIGNING_KEY`. The key is the UTF-8 bytes of that string (it is not hex-decoded). Minimum length is 16 bytes. It is not written into receipts. Treat it as a secret.

Receipt fields (JSON object, `v` = 1): `receipt_id`, `timestamp` (UTC), `agent_id`, `session_id`, `event` (`trap` or `clean`), `decoys` (objects with `id` and `type` only), `trigger_reason`, `signature` (hex HMAC-SHA256). The MAC covers the UTF-8 canonical JSON of every field except `signature` (`sort_keys=True`, separators `,` and `:`). Unknown fields fail verification. A trap receipt lists only the decoys that matched. A clean receipt lists every decoy registered at scan time. Clean receipts are off unless `emit_clean_receipts=True`. `agent_id` and `session_id` are null when omitted.

Synthetic patterns this package mints:

| Type | Value shape |
|------|-------------|
| `aws_access_key` | `AKIA-HONEY-` + 16 uppercase alphanumeric characters |
| `api_token` | `hp_honey_` + 32 hex characters |
| `generic_secret` | `HONEY-SECRET-` + 24 hex characters |
| `database_url` | `postgres://honey:HONEY-…@decoy.invalid:5432/honeyprompt` |

`decoy.invalid` is a reserved name, not a routable production host. The registry is append-only in Phase 1.

Scanned response paths: `choices[].message.content`, `choices[].message.tool_calls` function name and arguments, `choices[].text`, top-level `output_text`, and `output[]` text, name, and arguments. Plain strings are scanned as output text. Before the model call, prior `assistant`, `tool`, and `function` messages are scanned. System text planted by the injector is not treated as a leak. User messages are not treated as a leak.

`chat.completions.create` keyword `stream=True` raises `ValueError` and does not call the model. Prior assistant/tool messages are scanned first, so a decoy already in the cascade raises `HoneyTrapTriggeredException` instead of the stream error. Async `create` that returns a coroutine is awaited and then scanned.

### Limitations

- Supabase, the SOC dashboard, and CEF webhooks are later phases and are not in this package.
- Wrapping `chat.completions.create` does not protect other client methods.
- Streamed completions are refused rather than scanned.
- A leak that never repeats the synthetic value is not detected.

## Security notes

- Decoys are synthetic (for example `AKIA-HONEY-…`). Never store real production secrets as decoys. Minting does not take an external secret. `register` accepts only values that match a synthetic pattern, and it does not echo a refused value.
- Receipts are HMAC-SHA256 signed. Treat the signing key as a secret.
- No auto-exploit, no unlawful access. This is defensive tooling only.

## Status

Phase 1 Python SDK is done in this repo (`honeyprompts`: decoy registry, injector, interceptor kill-switch, HMAC-SHA256 receipts, tests, and an offline example). Phases 2–4 are not started. `supabase/`, `dashboard/`, `api/`, and `docs/` are not present.

Repo: https://github.com/Senior3514/HoneyPrompt
