# Archived Branches

This file records the **`archive/*`** branches on the fork. They were renamed from
their original names on 2026-04-18 because their content had already landed on
`main` (via merge, squash-merge, cherry-pick, or an independent re-implementation),
or because they were explicitly superseded by another PR. The tip commits are
preserved under the `archive/` prefix so history and tip SHAs remain accessible;
no commits were lost.

Hermes / dangerous-command approval branches (Issue #14 family) are **not**
covered here — they are active work tracked in PR #21.

---

## Group A — Tip is already an ancestor of `main`

`git merge-base --is-ancestor <branch> main` returns true, so every commit on
the branch is reachable from `main`.

| Archived name | Original tip | Original subject |
|---|---|---|
| `archive/feat/403-auto-retry` | `77455ef` | feat: auto-retry on 403 with two-tier backoff (3x1min + 2x5min) |
| `archive/feat/askuser-buttons` | `161a398` | fix: add update_multi:true to card config so buttons survive re-render |
| `archive/feat/fresh-session` | `8d533ba` | feat: add freshSession option for scheduled tasks |
| `archive/feat/issue-5-thinking-effort-card` | `dd1089d` | feat: configurable thinking/effort per bot and display model info in cards (#5) |
| `archive/feat/issue-8-effort-command` | `a5a4ba6` | feat: add /effort command for runtime effort level switching (#8) |
| `archive/feat/merge-upstream-main` | `a41799a` | fix: restore docs site URL to xvirobotics.com/metabot |
| `archive/feat/model-command` | `61f195a` | feat: add /model command to switch Claude model at runtime |
| `archive/feat/strip-markdown-in-tables` | `52e98df` | feat: strip Markdown formatting from Feishu table cells |
| `archive/fix/askuser-and-exitplanmode` | `32a6b4e` | fix: updateCard boolean contract + resolveQuestion race/leak (#7) |
| `archive/fix/install-skills-redundancy` | `4e94f50` | fix: stop copying redundant skills to per-bot directories (#25) |
| `archive/fix/preserve-card-on-restart` | `758bdc8` | fix: preserve card content on service restart |
| `archive/fix/preserve-qa-history` | `37fab04` | feat: include options list + highlight selected in Q&A history |
| `archive/fix/recreate-card-race` | `7d9349e` | fix: close recreateCard freeze race with RateLimiter pause/resume (#11) |

## Group B — Tip subject has exact match on `main`

Content landed via a commit with the same subject line (squash-merge or
cherry-pick with identical message).

| Archived name | Original tip | Landed on `main` as |
|---|---|---|
| `archive/codex` | `3f09bed` | `ab73f42` — fix: prevent updateCard crash and add WS heartbeat reconnect |
| `archive/fix/updatecard-crash-and-ws-heartbeat` | `3f09bed` | `ab73f42` (same commit as `archive/codex`) |
| `archive/feat/issue-161-auto-split-long-msgs` | `0d7ef92` | `4bce011` — feat: auto-split long responses into multiple Feishu cards (#161) |
| `archive/fix/ask-user-question-and-feishu-retry` | `0104542` | `c10eeea` — fix: AskUserQuestion support via PreToolUse hook + Feishu 502 retry |
| `archive/fix/enable-mcp-servers` | `bc9036e` | `651c40e` — fix: enable MCP servers from .mcp.json in SDK mode |
| `archive/fix/issue-163-vitest-undici` | `a8f7a76` | `00696c7` — fix: add vitest config to externalize undici module (#163) |

## Group C — Squash-merged via PR (tip no longer ancestor, but diff empty)

| Archived name | Original tip | Evidence |
|---|---|---|
| `archive/feat/issue-4-default-opus-4-7` | `e25db97` | PR #5 squash-merged to `main 2673498`; `git diff archive/feat/issue-4-default-opus-4-7 main -- bots.json` is empty |

## Group D — Subject differs but feature verified on `main`

These branches have commit subjects that do not appear on `main`, but the
feature/fix is present under a different implementation or different commit
message. Evidence was collected by grepping `main` for signature code.

| Archived name | Original tip | Evidence that feature is on `main` |
|---|---|---|
| `archive/feat/per-turn-message-splitting` | `9728971` | PR #3 squash-merged the initial commit as `b2278ca`. The 7 follow-up commits on this branch (buffer short turns, embed turn content in frozen cards, dedup result, etc.) are also present on `main`: `src/bridge/message-bridge.ts` contains `TURN_MERGE_THRESHOLD = 300` (7 references) and `tests/card-flow.test.ts` contains the `recreateCard — turn content in frozen card` describe block. |
| `archive/feat/feishu-table-rendering` | `fe96c09` | `main`'s `src/feishu/card-builder.ts` already uses `data_type: 'lark_md'` for cell rendering plus `stripMarkdown(h)` for headers (6 references), and is more complete than this branch (also strips markdown in row cells and sanitizes lark_md image syntax). |
| `archive/fix/readme-links` | `bc7e528` | This branch rewrites README links to `Shiien/metabot` (wrong fork name). `main`'s `README.md` already uses the correct `Liyunlun/metabot` (3 references; 0 references to Shiien). |
| `archive/fix/rate-limiter-ordering` | `13d99b5` | PR #8 was closed by the author on 2026-04-17 with the note "the rate-limiter fix alone is insufficient: the thinkingTimer keeps scheduling updates during recreateCard execution, so new stale updates still race the freeze after flush() returns. Will re-attempt in fix/recreate-card-race." The replacement PR #11 (`fix: close recreateCard freeze race with RateLimiter pause/resume`) was merged to `main` as `7d9349e`. |

---

## Verification method

Each archived branch was checked using one of four independent signals — in
order of rigor:

1. **Ancestor check** — `git merge-base --is-ancestor <branch> main`. If true,
   every commit is reachable from `main`. (Group A.)
2. **Exact subject match** — `git log main --format='%s' | grep -xF "<tip subject>"`
   catches squash-merges and cherry-picks that preserve the commit message.
   (Group B.)
3. **PR squash + empty diff** — for PRs that were squash-merged with `(#n)`
   suffixes added to the subject, verify the merge commit exists on `main` and
   that `git diff <branch> main -- <changed-files>` is empty. (Group C.)
4. **Content grep** — for branches whose subjects differ from `main`, grep
   `main` for signature code (test describe block, named constant, URL
   substring) from the branch's changes. (Group D.)

Patch-id matching (`git patch-id`) was **not** used as a standalone signal
because squash-merges produce a different patch-id.
