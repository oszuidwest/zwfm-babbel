# TTS Settings Decision Log

## 2026-06-06

- Added `ActorUserID` to the service-layer update request instead of making the service import Gin/auth. This preserves package layering while allowing audit logs to include `user_id`.
- Added an unexported `baseURL` field to `internal/tts.Service` so unit tests can assert the exact ElevenLabs request body through `httptest` without changing production configuration.
- Committed `docs/TTS_SETTINGS_PLAN.md` with the PR because it is the active implementation spec for this worktree and was not otherwise present on the branch.
- Kept `api_key_configured` derived from loaded config (`h.config.TTS.APIKey != ""`) rather than reading the environment again in the handler, so responses reflect the same config snapshot used to create the TTS client.
- Did not force-add `CLAUDE.md` because the repository intentionally ignores it. The local file was updated for workspace guidance, while commit-visible documentation lives in `openapi.yaml`, generated API docs, and this decision log.
