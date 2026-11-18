---
name: evolved-antigravity-cli-ops
description: "Operate, wrap, or integrate with Antigravity CLI (agy), including stream-json handling, prefix caching, observer recursion bypass, transcript telemetry, and custom skills."
---

# Antigravity CLI Operations & Integration

Operational guidelines for wrapping, automating, and integrating with Antigravity CLI (`agy`) background processes, telemetry, hooks, and skill systems.

## 1. Stream-JSON Status Contract & Compaction Handling
- **Missing or Null Status**: Antigravity CLI's `stream-json` mode can emit `status: null` on successful operation completions (including `/compact`). Avoid strict equality checks like `res.get("status") == "SUCCESS"`.
- **Success Predicate**: Evaluate success as `status in (None, "SUCCESS") and not res.get("error")`.
- **Compaction Loop Prevention**: When managing turn/token compaction triggers in daemon wrappers (e.g., `COMPACT_MAX_TURNS`, `COMPACT_MAX_TOKENS`), unconditionally reset internal counters (`turns_since_compact = 0`, `last_active_tokens = 0`) across all exit paths upon issuing `/compact` to prevent infinite compaction loops.

## 2. Prompt Envelope Architecture & Prefix Caching
- **Static Template Prefix**: Avoid dynamic tokens, UUIDs (`uuid.uuid4().hex`), or variable timestamps inside leading prompt headers (e.g., `<STATELESS_TASK id="...">`).
- **Cache Hit Maximization**: Keep system instructions and outer envelopes static across repeated invocations to allow underlying LLM providers to utilize prompt prefix caching, drastically reducing token latency and quota burn.

## 3. Observer Bypass in Daemons & Hooks
- **Preventing Recursive Loops**: When invoking `agy` from background daemons, systemd services, or hook scripts (e.g., pre/post invocation hooks), set `Environment=AGY_INTERNAL_OBSERVER=1` or export `AGY_INTERNAL_OBSERVER=1`.
- **Hook Short-Circuiting**: Check for `AGY_INTERNAL_OBSERVER=1`, observer sandbox working directories, or known shim conversation IDs at the start of hooks to return early and prevent circular tracking and token inflation.

## 4. Transcript Telemetry and Token Accounting
- **Dual Step Filtering**: Antigravity CLI records token usage across multiple event types in `transcript.jsonl`. Always filter for both `PLANNER_RESPONSE` and `CHECKPOINT` entry types.
- **Accurate Quota Auditing**: Checkpoint events carry significant uncached token metrics from background auto-compactions that are missed if only planner events are parsed.

## 5. Concurrent SQLite Database Access
- **Read-Only Mode**: When background bridges or reporting tools inspect `~/.gemini/antigravity-cli/conversation_summaries.db`, connect using SQLite URI read-only mode (`file:...mode=ro`, `uri=True`).
- **Contention Avoidance**: Read-only connections prevent database locking errors and contention with running CLI sessions.

## 6. Workspace Registration and Custom Skill Layout
- **Project Binding**: To register a persistent workspace, add the directory to `trustedWorkspaces` in `~/.gemini/antigravity-cli/settings.json`, then execute `agy --new-project` inside that directory to create a persistent project ID in `~/.gemini/config/projects/`.
- **Skill Structure**: Place custom skills in `.agents/skills/<skill-name>/SKILL.md` (with YAML frontmatter `name` and `description`), executable implementation scripts in `scripts/`, and symlink entrypoints into `~/.local/bin/`.
