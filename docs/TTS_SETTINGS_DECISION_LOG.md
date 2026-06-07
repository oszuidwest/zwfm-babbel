# TTS Settings Decision Log

## 2026-06-06

- Added `ActorUserID` to the service-layer update request instead of making the service import Gin/auth. This preserves package layering while allowing audit logs to include `user_id`.
- Added an unexported `baseURL` field to `internal/tts.Service` so unit tests can assert the exact ElevenLabs request body through `httptest` without changing production configuration.
- Committed `docs/TTS_SETTINGS_PLAN.md` with the PR because it is the active implementation spec for this worktree and was not otherwise present on the branch.
- Kept `api_key_configured` derived from loaded config (`h.config.TTS.APIKey != ""`) rather than reading the environment again in the handler, so responses reflect the same config snapshot used to create the TTS client.
- Did not force-add `CLAUDE.md` because the repository intentionally ignores it. The local file was updated for workspace guidance, while commit-visible documentation lives in `openapi.yaml`, generated API docs, and this decision log.

## 2026-06-07

- Mapped ElevenLabs 401/403/429/5xx as service availability problems rather than request validation: 401/403 become 503 upstream failures, 429 becomes a typed rate-limit error with `Retry-After`, and other upstream status codes become 502.
- Split missing `tts_settings` schema from missing singleton row. A missing table still points admins to migration `005_tts_settings.sql`; a deleted `id=1` row now returns `tts_settings.row_missing` with a re-seed hint.
- Kept admin PATCH writes as last-writer-wins and documented the audit-log tradeoff in code instead of introducing `SELECT ... FOR UPDATE`; this matches the existing PATCH behavior elsewhere in the API.
- Kept the handler/service seed DTO as signed `int64` so negative JSON values produce field validation errors, but convert to `uint32` before repository/model writes to match the ElevenLabs and database domain.
- Default model stays `eleven_v3` paired with the v3-style prefix `[professional][news anchor][engaging]`. Switching the default to `eleven_multilingual_v2` or `eleven_flash_v2_5` requires clearing the prefix simultaneously, because non-v3 models read bracketed style directives literally.
