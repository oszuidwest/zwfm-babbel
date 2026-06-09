# Open Issues Triage - 2026-06-09

Scope:

- Repository: `oszuidwest/zwfm-babbel`
- Branch checked: `main`
- Commit checked: `5f64fa90b3b454e5e2cbf48b01b07ad1c6678ca3` (`clean-up: implement TTS v3 pronunciation rules only (#213)`)
- GitHub REST issue list returned 13 open non-PR issues. All had zero comments at time of fetch.

Legend:

- **Aanpakken**: still worth doing now or in the next cleanup/security pass.
- **Conditioneel**: keep, but do not build until an external trigger/decision is true.
- **Sluiten**: obsolete, already satisfied, or superseded by current `main`.

## Executive Summary

| Issue | Oordeel | Advies |
| --- | --- | --- |
| [#183](https://github.com/oszuidwest/zwfm-babbel/issues/183) | Aanpakken | Highest-value hardening: `BindAndValidate` still lacks the 1 MiB body cap used by strict/optional binders. |
| [#214](https://github.com/oszuidwest/zwfm-babbel/issues/214) | Aanpakken | Valid architecture cleanup: pronunciation rules handler still binds directly into a service DTO with HTTP tags. |
| [#200](https://github.com/oszuidwest/zwfm-babbel/issues/200) | Aanpakken | Cheap defensive safety fix: `int64` to `uint32` conversion still relies on caller contract. |
| [#207](https://github.com/oszuidwest/zwfm-babbel/issues/207) | Aanpakken | Still valid test-hardening, but update wording from model enum to `apply_text_normalization`. |
| [#202](https://github.com/oszuidwest/zwfm-babbel/issues/202) | Aanpakken | Tiny docs/runbook task; migration discipline is being followed but not documented. |
| [#175](https://github.com/oszuidwest/zwfm-babbel/issues/175) | Aanpakken, rescope | Partially implemented; not done against original acceptance criteria. |
| [#204](https://github.com/oszuidwest/zwfm-babbel/issues/204) | Aanpakken of watch | Still real but low risk. A one-line invariant comment is enough. |
| [#201](https://github.com/oszuidwest/zwfm-babbel/issues/201) | Conditioneel | Needs ops/compliance decision. Code now logs old/new values, but no persisted audit table exists. |
| [#203](https://github.com/oszuidwest/zwfm-babbel/issues/203) | Conditioneel | Keep as watch. No cache exists, but current load trigger is not proven. |
| [#206](https://github.com/oszuidwest/zwfm-babbel/issues/206) | Conditioneel | Keep as watch. One HTTP attempt remains; build retries only on volume/incident trigger. |
| [#210](https://github.com/oszuidwest/zwfm-babbel/issues/210) | Gesloten 2026-06-09 | Closed: adapter leak resolved by #213. |
| [#211](https://github.com/oszuidwest/zwfm-babbel/issues/211) | Gesloten 2026-06-09 | Closed: dictionary flow/CAS path removed by #213 + migration 008. |
| [#205](https://github.com/oszuidwest/zwfm-babbel/issues/205) | Gesloten 2026-06-09 | Closed: only `eleven_v3` remains; migration 008 dropped the `model` column. |

## Recommended Order

1. **#183** - security/resource hardening with broad endpoint impact.
2. **#214** - architecture cleanup while pronunciation-rules code is fresh.
3. **#200 + #207 + #202** - small, low-risk cleanup batch.
4. **#175** - meaningful feature work; keep open but rewrite around what is still missing.
5. **#204** - either close with an invariant comment or keep as watch.
6. **#201/#203/#206** - leave open only if the project uses watch/decision tickets deliberately.
7. ~~**Close #210/#211/#205** with references to #213/current `main`.~~ Done 2026-06-09.

## Detailed Triage

### #214 - keep PronunciationRules HTTP binding out of service layer

**Oordeel: Aanpakken.**

The issue is still current. `internal/api/handlers/pronunciation_rules.go:38-39` still declares `var req services.UpdatePronunciationRulesRequest` and passes it to `utils.BindJSONStrict`. `internal/services/pronunciation_rules_service.go:52-63` still gives the service input JSON tags and a Gin `binding:"required"` tag.

This is not a runtime bug, but the layering smell remains. It is also now more isolated: #213 removed the old ElevenLabs dictionary adapter coupling, so the remaining cleanup is specifically HTTP binding leakage.

Recommended action: introduce a handler-level or utils-level request DTO and map into a tag-free service request. Keep service validation in `materializePronunciationRules`.

### #211 - cleanup orphan ElevenLabs pronunciation dictionaries on CAS loss

**Status: Gesloten 2026-06-09.**

**Oordeel: Sluiten als obsolete/superseded.**

The issue describes a code path that no longer exists on `main`. Commit #213 deleted `internal/tts/pronunciation_dictionary.go` and `internal/tts/pronunciation_dictionary_test.go`. The current pronunciation rules service stores local DB rows (`internal/services/pronunciation_rules_service.go`) and no longer calls an ElevenLabs pronunciation dictionary API. `migrations/008_drop_legacy_tts_settings_columns.sql` drops `pronunciation_dictionary_id`.

There is no `PronunciationDictionaryClient`, `ArchiveDictionary`, `CreateDictionaryFromRules`, `SetRules`, or CAS persist path left to fix.

Recommended action: close as superseded by #213. If production ever created orphan dictionaries under the previous implementation, that is an ops cleanup note, not this code issue.

### #210 - stop leaking internal/tts types through PronunciationRules service and handler

**Status: Gesloten 2026-06-09.**

**Oordeel: Sluiten als already satisfied/superseded.**

The handler no longer imports `internal/tts`; `internal/api/handlers/pronunciation_rules.go:3-10` imports Gin, auth, models, services, utils only. `PronunciationRulesResponse.Rules` is `[]models.PronunciationRule` in `internal/services/pronunciation_rules_service.go:66-70`. Handler mapping takes `models.PronunciationRule` at `internal/api/handlers/pronunciation_rules.go:67`.

The exact acceptance criteria around removing `tts.Rule` leakage are met. The service currently uses `models.PronunciationRule` rather than a separate service-domain struct; that is acceptable for this issue because the adapter leak is gone.

Recommended action: close with a note that #213 removed the adapter dependency.

### #207 - enum-message coverage + field-order brittleness

**Oordeel: Aanpakken, with updated wording.**

Part (a) is still current: `internal/services/tts_settings_service_test.go:65` still uses `slices.Equal(gotFields, tt.wantFields)`, so validator order changes can break the test without behavior changing.

Part (b) is still conceptually current, but the specific enum changed. There is no configurable TTS model enum now; `allowedTextNormalizations` drives `enumMessage` in `internal/services/tts_settings_service.go:156-176`. Current tests assert invalid field names but not that the returned enum message contains every allowed value.

Recommended action: switch field comparison to set equality and add one invalid `apply_text_normalization` test that asserts the message includes `auto`, `on`, and `off`.

### #206 - resilience for ElevenLabs TTS client

**Oordeel: Conditioneel/watch.**

The current client still performs one `s.client.Do(req)` per `GenerateSpeech` call (`internal/tts/elevenlabs.go:127`) and directly returns an `APIError` for non-200 responses. `Retry-After` is captured (`internal/tts/elevenlabs.go:141-145`) and surfaced through service tests, but no retry/backoff/circuit breaker exists.

That matches the issue's watch state. No repo evidence proves the trigger is true: volume over roughly 10 calls/minute or a production 429/5xx incident.

Recommended action: keep as watch if such tickets are useful; otherwise close until a real incident/volume signal exists. Do not implement proactively unless operational evidence changed.

### #204 - float equality in changedTTSSettingsFields

**Oordeel: Low-risk cleanup or keep watch.**

The exact equality checks remain at `internal/services/tts_settings_service.go:254-257`. The issue's risk assessment is still accurate: today both values come from DB reads around an update, and no arithmetic is involved, so equality is deterministic enough for current behavior.

Recommended action: either add the invariant comment near the comparison and close, or keep as watch. `math.Float64bits` would be defensive but not meaningfully stronger for `DECIMAL(3,2)` values read from the same source.

### #205 - refactor model-specific branches to Model type when N >= 3

**Status: Gesloten 2026-06-09.**

**Oordeel: Sluiten als obsolete.**

The original trigger depended on multiple model-specific branches around `settings.Model`. That shape is gone. Current `internal/tts/elevenlabs.go:21-26` declares `ModelV3` as the only supported model. The request always sends `ModelID: ModelV3` at `internal/tts/elevenlabs.go:103-106`. `migrations/008_drop_legacy_tts_settings_columns.sql` drops `model` and `use_speaker_boost`.

Recommended action: close as superseded by the v3-only simplification. Reopen a fresh design issue only if multi-model support returns.

### #203 - in-memory cache for tts_settings singleton

**Oordeel: Conditioneel/watch.**

`StoryService.GenerateTTS` still calls `s.ttsSettingsSvc.Get(ctx)` for every TTS request at `internal/services/story_service.go:443`. No in-memory cache or invalidate-on-PATCH exists in `TTSSettingsService`.

The issue itself says this is acceptable until high TTS load or DB latency pressure appears. That trigger is not inferable from the codebase.

Recommended action: keep as watch only if the team tracks capacity triggers in GitHub. Do not build now without runtime metrics.

### #202 - migration 005 frozen post-merge

**Oordeel: Aanpakken as tiny documentation task.**

The migration discipline appears to be followed: later removal of `model`, `pronunciation_dictionary_id`, and `use_speaker_boost` is represented as `migrations/008_drop_legacy_tts_settings_columns.sql`, not by editing the deployed shape into `005`.

However, the requested "one-line note" is not present in `CLAUDE.md`, README, docs, scripts, or a migrations README. `CLAUDE.md` documents `migrations/` generally but not the "after merge, never rewrite numbered migrations" rule.

Recommended action: add a short `migrations/README.md` or CLAUDE note. This is still opportune because it prevents future accidental history edits.

### #201 - persistent audit trail for tts_settings PATCH

**Oordeel: Conditioneel decision ticket.**

The issue text is partly stale. Current `TTSSettingsService.Update` logs richer audit data than "changed_fields only": `buildTTSSettingsAuditFields` records `old_<field>` and `new_<field>` for changed fields (`internal/services/tts_settings_service.go:223-243`). The comment at `internal/services/tts_settings_service.go:75-77` states the log is the system of record.

There is still no persisted `tts_settings_audit` table or insert path.

Recommended action: do not implement by default. Ask ops/compliance whether logs are retained at least 30 days and searchable by `user_id`. If yes, close as won't-do with that rationale. If no, build the audit table.

### #200 - defensive bounds check in seedUpdateValue

**Oordeel: Aanpakken.**

`seedUpdateValue` still casts `int64` to `uint32` at `internal/services/tts_settings_service.go:147-153` and relies on `validateSeed` having run earlier. `rg` finds only one call site today (`internal/services/tts_settings_service.go:98`), so the risk remains low, but the defensive fix is cheap.

Recommended action: add the inline bounds check and probably a small unit test. This is a good small cleanup to batch with #207.

### #183 - Harden BindAndValidate with request body size cap

**Oordeel: Aanpakken; highest priority.**

The issue is still current. `utils.BindAndValidate` decodes directly from `json.NewDecoder(c.Request.Body)` at `internal/utils/http.go:303-305`. By contrast, `BindJSONStrict` wraps the body with `http.MaxBytesReader` at `internal/utils/http.go:317`, and `BindOptionalJSON` uses the same cap at `internal/utils/http.go:475`.

Blast radius is broad. `BindAndValidate` is still used by stations, voices, station voices, stories, and users handlers. Oversized scalar JSON can still be materialized before validation.

Recommended action: factor a shared capped decoder/reader helper and preserve the existing error shape where tests expect it. Add a targeted oversized-body test for `BindAndValidate`.

### #175 - Make story audio levels automatically consistent

**Oordeel: Aanpakken, but rewrite as partial-completion follow-up.**

Current code has moved significantly toward the goal:

- `ConvertStoryToWAV` exists and routes story upload/TTS audio through story-specific processing (`internal/audio/audio.go:58-66`, `internal/services/story_service.go:375-377`).
- `loudnorm=I=-16:TP=-1:LRA=11` is applied (`internal/audio/audio.go:23-25`).
- There is an additional true-peak correction path and tests for true peak (`internal/audio/audio.go:95-147`, `internal/audio/audio_test.go:84-131`, `tests/stories/stories.test.js:360-390`).
- TTS output enters the same story audio pipeline (`internal/services/story_service.go:465-476`).

But it is not complete against the original acceptance criteria:

- No two-pass loudnorm implementation using `measured_I`, `measured_TP`, `measured_LRA`, `measured_thresh`, and `offset`.
- Parser/test coverage only reads `input_tp`; it does not validate `input_i`, `input_lra`, `input_thresh`, or `target_offset`.
- Tests assert true peak but not integrated loudness convergence for quiet and loud inputs.
- Silent/effectively silent input is not rejected; `storyTruePeakGain` treats `-inf` true peak as zero gain.
- Jingle handling is not cleanly separated in policy/tests; `ConvertToWAV` still applies loudnorm for station voice jingle uploads.

Recommended action: keep open but update the body/title to "finish story loudness normalization acceptance criteria". Treat the remaining work as non-trivial feature hardening, not a quick bugfix.

