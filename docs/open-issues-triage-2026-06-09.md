# Open Issues Triage - 2026-06-09 Refresh

Scope:

- Repository: `oszuidwest/zwfm-babbel`
- Triage branch: `docs/open-issues-triage-2026-06-09`
- Base checked: `origin/main`
- Base commit checked: `78ec7aadaab7` (`fix: cap BindAndValidate JSON bodies (#215)`)
- Data source: GitHub issues and PRs fetched on 2026-06-09.
- Current GitHub issue list returned 5 open non-PR issues.

Legend:

- **Address**: still worth doing now or in the next focused cleanup pass.
- **Decision needed**: keep open until an operational or compliance decision is recorded.
- **Watch**: keep only if the documented trigger is useful to track; do not implement proactively.
- **Closed**: already resolved, obsolete, or superseded by current `main`.

## Executive Summary

| Issue | Status | Assessment | Advice |
| --- | --- | --- | --- |
| [#221](https://github.com/oszuidwest/zwfm-babbel/issues/221) | Open | Address | Small but useful audit-integrity test gap. Cover `ActorUserID` propagation from the pronunciation-rules handler into the service request. |
| [#175](https://github.com/oszuidwest/zwfm-babbel/issues/175) | Open | Address, scoped | The current code has story-specific normalization and true-peak handling, but it still does not meet the original two-pass loudnorm and unusable-audio criteria. |
| [#201](https://github.com/oszuidwest/zwfm-babbel/issues/201) | Open | Decision needed | Current structured logs include old and new values. Decide whether log retention/searchability is enough before adding a persisted audit table. |
| [#203](https://github.com/oszuidwest/zwfm-babbel/issues/203) | Open | Watch | No cache exists, but the current singleton read is acceptable until TTS load or DB latency makes it measurable. |
| [#206](https://github.com/oszuidwest/zwfm-babbel/issues/206) | Open | Watch | The ElevenLabs client still makes one HTTP attempt. Implement retries only after the documented volume or incident trigger. |

Current practical order:

1. **#221** - fastest open cleanup with a concrete regression risk.
2. **#175** - only substantial feature-hardening item still open.
3. **#201** - close or implement after an ops/compliance retention decision.
4. **#203/#206** - leave as watch tickets only if the team wants trigger-based capacity tracking in GitHub.

## What Changed Since The Original Triage

The original document reviewed 13 open issues against `main` at PR `#213`. Most of the actionable cleanup items have since been resolved and closed:

| Issue | Closed by | Current note |
| --- | --- | --- |
| [#183](https://github.com/oszuidwest/zwfm-babbel/issues/183) | [#215](https://github.com/oszuidwest/zwfm-babbel/pull/215) | `BindAndValidate` now uses the shared capped JSON decoder and returns 413 for oversized JSON bodies. |
| [#214](https://github.com/oszuidwest/zwfm-babbel/issues/214) | [#216](https://github.com/oszuidwest/zwfm-babbel/pull/216) | Pronunciation-rules HTTP binding now maps through a handler/request DTO instead of binding directly into the service request. |
| [#200](https://github.com/oszuidwest/zwfm-babbel/issues/200) | [#217](https://github.com/oszuidwest/zwfm-babbel/pull/217) | `seedUpdateValue` now keeps a defensive bounds check before converting to `uint32`. |
| [#207](https://github.com/oszuidwest/zwfm-babbel/issues/207) | [#218](https://github.com/oszuidwest/zwfm-babbel/pull/218) | TTS settings validation tests were hardened for enum-message coverage and order-insensitive field checks. |
| [#202](https://github.com/oszuidwest/zwfm-babbel/issues/202) | [#219](https://github.com/oszuidwest/zwfm-babbel/pull/219) | Migration freeze discipline is now documented. |
| [#204](https://github.com/oszuidwest/zwfm-babbel/issues/204) | [#220](https://github.com/oszuidwest/zwfm-babbel/pull/220) | The intentional float-equality invariant is documented near the comparison. |
| [#205](https://github.com/oszuidwest/zwfm-babbel/issues/205) | [#213](https://github.com/oszuidwest/zwfm-babbel/pull/213) | Obsolete after the v3-only simplification removed configurable model branching. |
| [#210](https://github.com/oszuidwest/zwfm-babbel/issues/210) | [#213](https://github.com/oszuidwest/zwfm-babbel/pull/213) | The pronunciation-rules handler/service no longer leak `internal/tts` rule types. |
| [#211](https://github.com/oszuidwest/zwfm-babbel/issues/211) | [#213](https://github.com/oszuidwest/zwfm-babbel/pull/213) | Obsolete after the external pronunciation-dictionary flow was removed. |

## Detailed Triage

### #221 - cover ActorUserID propagation on PUT /settings/tts/pronunciations

**Assessment: Address.**

This is the clearest remaining small follow-up. `UpdatePronunciationRules` builds a service request from the HTTP DTO and then copies the authenticated user ID into `serviceReq.ActorUserID` when `auth.UserID(c)` is present. `logPronunciationRulesAudit` later uses that value to write `user_id` into the audit log.

Current handler tests cover strict binding, pointer/default semantics, response mapping, and service error handling. They do not set an auth context and therefore do not fail if the handler stops copying `ActorUserID`.

The issue correctly notes the testability friction: `Handlers.pronunciationRulesSvc` is still a concrete `*services.PronunciationRulesService`, so a request-capturing fake cannot be swapped in without a small interface extraction or test-only seam.

Recommended action:

- Introduce a small unexported handlers-package interface for the pronunciation-rules service methods the handlers need: `Get` and `Update`.
- Keep `services.PronunciationRulesService` satisfying that interface naturally.
- Add a fake service in `pronunciation_rules_test.go` that captures the `*services.UpdatePronunciationRulesRequest`.
- Add table-driven tests for auth present and auth absent.

Done when removing the `serviceReq.ActorUserID = &userID` assignment makes the new test fail.

### #175 - make story audio levels automatically consistent

**Assessment: Address, but keep it scoped as feature hardening.**

Current `main` has meaningful partial progress:

- `ProcessAudio` routes story uploads through `ConvertStoryToWAV`.
- Generated TTS audio also enters the story-audio pipeline through `ProcessAudio`.
- Story audio is converted to mono WAV, 48 kHz, PCM 16-bit.
- The current filter applies `loudnorm=I=-16:TP=-1:LRA=11`.
- A true-peak measurement path exists, and an extra volume correction is applied when needed.

The issue is still open because the original acceptance criteria are broader than the current implementation:

- The implementation does not run FFmpeg `loudnorm` in two-pass mode with explicit `measured_I`, `measured_TP`, `measured_LRA`, `measured_thresh`, and `offset` values.
- `loudnormStats` only parses `input_tp`; it does not validate integrated loudness, loudness range, threshold, or target offset.
- Silent or effectively silent input is not rejected. A `-inf` true-peak measurement currently produces zero extra gain rather than an explicit validation failure.
- Existing tests cover true-peak behavior, but they do not prove quiet and loud inputs converge to comparable integrated loudness around `-16 LUFS`.
- Jingle handling remains a separate policy question: `ConvertToWAV` still applies loudnorm for non-story uploads, while `ConvertStoryToWAV` is story-specific.

Recommended action:

- Reframe the issue body, or a follow-up PR description, around the remaining acceptance criteria rather than treating the whole feature as missing.
- Implement full loudnorm measurement parsing before changing behavior.
- Add tests for quiet input, loud input, unusable/silent input, and integrated loudness convergence.
- Keep jingle policy explicitly out of scope unless the team wants to change non-story audio handling too.

### #201 - persistent audit trail for tts_settings PATCH

**Assessment: Decision needed.**

The original concern is partly addressed by current code. `TTSSettingsService.Update` logs a structured audit entry after a successful update. `buildTTSSettingsAuditFields` records `changed_fields` and old/new values for each changed setting. The service comment explicitly states that the log is the system of record for who changed what.

There is still no persisted `tts_settings_audit` table or database insert path.

Recommended decision:

- If production logs are retained for at least 30 days and searchable by `user_id`, close this as won't-do with that rationale.
- If retention or searchability is not guaranteed, implement the audit table and insert inside `Update` after the successful write and reload.

Do not build this by default without the retention decision. A database audit trail has schema and storage cost, and the current log-only design is already explicit.

### #203 - in-memory cache for tts_settings singleton

**Assessment: Watch.**

`StoryService.GenerateTTS` still calls `ttsSettingsSvc.Get(ctx)` for every TTS generation request. No in-memory cache or invalidate-on-PATCH path exists.

That is acceptable for the current described usage. The singleton row is read by primary key, and TTS generation is admin-triggered and low frequency. The issue's own trigger remains the right boundary: sustained high TTS load or a tighter DB latency budget.

Recommended action:

- Keep open only if the team wants watch tickets for capacity triggers.
- Prefer invalidate-on-PATCH over TTL if this is implemented later, because admins should see settings changes immediately.
- Close without implementation if GitHub should track only work that is already ready to do.

### #206 - resilience for ElevenLabs TTS client

**Assessment: Watch.**

`internal/tts/elevenlabs.go` still performs one `s.client.Do(req)` call per `GenerateSpeech` request. The client captures `Retry-After` in `APIError.RetryAfter`, and the service maps 429 responses to a rate-limited application error, but there is no retry, backoff, jitter, or circuit breaker.

That still matches the issue's watch state. Implementing retries now would add behavior and test complexity without repo evidence that the trigger has fired.

Recommended action:

- Keep open if the team wants an explicit incident/volume trigger.
- Implement retry-on-429 honoring `Retry-After` after the first production burst or volume increase.
- Add exponential backoff with jitter for transient 5xx responses at the same time.
- Consider a circuit breaker only if repeated upstream failures become operationally visible.

