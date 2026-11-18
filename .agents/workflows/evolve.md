---
description: Cluster high-confidence ECC instincts and evolve them into Antigravity skills (.agents/skills/)
---

1. Run `~/.local/bin/agy-instinct analyze-now` to capture any recent unanalyzed session observations.
2. Run `~/.local/bin/agy-instinct status` to inspect current instincts and confidence scores.
3. Run `~/.local/bin/agy-instinct evolve` to cluster high-confidence instincts via `gemini-3.8-flash-high` + `instinct-cli.py` and sync generated skills into `~/agy-workspace/.agents/skills/`.
4. Report newly evolved `SKILL.md` files and synced active instincts to the user.
