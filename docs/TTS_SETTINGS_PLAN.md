# TTS Settings — Implementation Plan

Status: design locked (v8 — seventh senior review iteration)
Scope reference: brought over the configurable TTS pieces from [`oszuidwest/babbel-ai-gen`](https://github.com/oszuidwest/babbel-ai-gen) into `zwfm-babbel` as UI-manageable settings. Everything outside TTS (OpenAI weather generation, OpenWeather, scheduler, rotation list, review/annotation UI) stays in `babbel-ai-gen`.

> **Revision note (v8 over v7).** One cleanup finding:
> 1. The singleton repo's custom `Update` must marshal the partial-update struct through `repository.BuildUpdateMap` (`update_helper.go:26`) and call `Updates(map[string]any)`, **not** `Updates(struct)`. GORM's `Updates(struct)` skips zero values, and several of our fields have semantically valid zero values: `stability=0`, `style=0`, `use_speaker_boost=false`, `tts_style_prefix=""`. Without the map conversion these would silently no-op. Pattern matches `voice_repository.go:56-61`.
>
> Earlier revisions:
> v7 over v6: `001_complete_schema.sql` needs `DROP TABLE IF EXISTS tts_settings;` in the drop section + plain `CREATE TABLE` (not `IF NOT EXISTS`) for `make db-reset` parity; duplicate revision history cleaned; OpenAPI contract scenario for PATCH `/settings/tts` is self-restoring (GET current → PATCH same value).
> v6 over v5: handler-local mapper (cycle); empty-body vs `{}` semantics; stale GET+POST spots → GET+PATCH+POST; custom singleton `Update` ignoring `RowsAffected`.
> v5 over v4: separate service DTO; empty-body 422; PATCH 503-path; `Resource` field on `ValidationProblemError`; test capture/restore + sequencer.
> v4 over v3: new `apperrors.ValidationProblemError` for the 422 service-layer path; 503 example body matches `ProblemExtended` output; `NotInitializedError` gains `Error()`/`Unwrap()`; handler-call name correction (`ProblemValidationError`).
> v3 over v2: DTO location to avoid `models → utils` cycle; single-owner prefix composition; rune-counting; missing-schema → 503 sentinel; validation problem shape; speed range tightened to 0.7–1.2; `pkg/logger` instead of raw `slog`.

---

## 1. Background

### What `babbel-ai-gen` does today

A standalone Go binary that runs daily at 12:00 Europe/Amsterdam and produces one `bulletin.wav` for ZuidWest FM:

1. Logs into the Babbel API (cookie session), fetches up to N active stories for `station_id=1`, `voice_id=7`.
2. Optionally generates a weather segment via OpenWeather + OpenAI Responses API (`gpt-5.5`).
3. Concatenates a script: `[professional][news anchor][engaging]` header + stories separated by `[long pause]` + weather text.
4. One ElevenLabs `eleven_v3` TTS call with `with-timestamps` + voice_settings (stability 0.8, similarity 0.8, style 0.25, speaker_boost on — silently ignored by v3 server-side) + alignment retry up to 3×.
5. Downloads the station-voice jingle from Babbel API, ffmpeg-mixes TTS into the jingle at `mix_point` to produce stereo `bulletin.wav`.
6. SQLite store with bulletins/words/annotations and an embedded review UI in the Go binary.

### What `zwfm-babbel` has today

- `Voice.ElevenLabsVoiceID` (per-voice).
- `TTSConfig` global, env-driven: `APIKey`, `Model` (default `eleven_multilingual_v2`), `RequestTimeout`.
- Per-story TTS endpoint: `POST /api/v1/stories/{id}/tts` — ElevenLabs MP3 → ffmpeg → mono WAV.
- `internal/tts/elevenlabs.go` is a **pure HTTP client** (imports stdlib + `internal/config` only).
- `internal/services/story_service.go:18` imports `internal/tts` and orchestrates the per-story TTS flow.
- Logging is centralized in `pkg/logger` (slog wrapper). `internal/` has zero direct `slog.X` call sites.
- Request DTOs live in `internal/utils/http.go` (e.g. `StoryCreateRequest`, `StoryUpdateRequest`). `internal/utils/http.go:21` imports `internal/models`, so `internal/models` must NOT import `internal/utils` (would create a cycle).
- No voice_settings (stability/similarity/style/speed/speaker_boost). No OpenAI. No weather. No rotation. No scheduler for bulletin generation. No alignment.

### What the new feature delivers

A globally-configurable, DB-driven set of ElevenLabs TTS parameters, manageable via REST (admin write, all roles read). The TTS package stays a thin HTTP client receiving the final composed text; `StoryService` owns settings fetching, prefix composition, and the rune-count cap check.

---

## 2. Decision log

| # | Decision | Choice | Reasoning |
|---|----------|--------|-----------|
| 1 | Architecture | Only TTS settings into Babbel; the rest stays in `babbel-ai-gen` | Smallest viable slice |
| 2 | Feature scope | ElevenLabs `voice_settings` + `model` + `tts_style_prefix` | `output_format`, OpenAI, weather, scheduler explicitly excluded |
| 3 | Multi-tenancy | Multi-station prepared, not active | Global singleton row now; station_id FK can be added later |
| 4 | Granularity | Global (one row in `tts_settings`) | One ElevenLabs voice in production; per-voice override is YAGNI today |
| 5 | Persistence | DB-driven, UI live editable | "Via the UI" requires DB, not env |
| 6 | Specific fields | `stability`, `similarity_boost`, `style`, `use_speaker_boost`, `speed`, `apply_text_normalization`, `seed`, `model`, `tts_style_prefix` | Each justified in §3 |
| 7 | API key handling | Env-only (`BABBEL_ELEVENLABS_API_KEY`) | Secrets are deployment concerns |
| 8 | Audio tags / style prefix | In scope as `tts_style_prefix`. Server uses it **only** when `model == "eleven_v3"`. **Prefix composition lives in `StoryService`**, not in `internal/tts` | Single owner for the final text; tts package stays a thin marshaller |
| 9 | Model selector | Hardcoded enum whitelist of **3 models**: `eleven_v3`, `eleven_multilingual_v2`, `eleven_flash_v2_5` | `eleven_turbo_v2_5` dropped (ElevenLabs Models page marks it "deprecated / outclassed by Flash") |
| 10 | Default model | `eleven_v3` (GA per ElevenLabs Models page, supports audio tags) | Combined with the rune-count cap in §5 |
| 11 | `output_format` | Out of scope — hardcoded `mp3_44100_128` | Babbel converts to 48 kHz mono WAV anyway |
| 12 | RBAC write | Admin only | Settings change production output globally |
| 13 | RBAC read | Admin + editor + viewer | No secrets in payload |
| 14 | Live behavior | Read-on-every-call from DB | Simplest model; performance fine for ZW volume |
| 15 | Validation contract | **422 + `utils.ProblemValidationError`** (the handler-side responder, not the `NewValidationProblem` builder) with title `"Validation Error"`, type `https://babbel.api/problems/validation-error`, and `errors[]` containing `{ field, message }` entries (no `code` field — matches existing `utils.ValidationError` shape exactly). Service-layer entry point is a new `apperrors.ValidationProblemError` (§5) | Conform to the project-wide problem shape; the new typed error is necessary because the existing `*apperrors.ValidationError` is mapped to 400 by `handleServiceError`, not 422 |
| 16 | Initial defaults | Seed row included in `001_complete_schema.sql`. **No runtime-seed in Go** | Fresh Docker init has settings out of the box; existing deploys must run the new migration manually |
| 17 | `BABBEL_ELEVENLABS_MODEL` env var | Deprecated — removed from code, `.env.example`, and `TTSConfig.Model` | Single source of truth (DB) |
| 18 | Per-call overrides | None | `POST /stories/{id}/tts` stays minimal (only `?force=true`) |
| 19 | Audit | `pkg/logger.Info` from the centralized logger (NOT raw `slog.Info` — codebase convention) | `internal/` has zero direct `slog` calls |
| 20 | Per-story settings snapshot | None | Global change → all subsequent stories get new behavior |
| 21 | UI placement | Separate frontend repo consumes the OpenAPI; no UI in this repo | Babbel is headless |
| 22 | `tts_style_prefix` length cap | **500 characters** (server validates via PATCH) | Prefix counts toward ElevenLabs character billing |
| 23 | Schema shape | Single-row typed-column table with `CHECK id = 1` | Type-safe, SQL-validated |
| 24 | Test strategy | **Hand-written Jest suite** | Schema-based generators (`CrudTestGenerator.js:17`) assume POST/list/id/PUT/DELETE — they don't fit a singleton |
| 25 | Concurrency | Last-write-wins (no `If-Match` / ETag) | Matches every other PATCH endpoint in the codebase |
| 26 | GET response | Includes `api_key_configured: bool` (never the value) | Pre-empts "settings look fine but TTS does nothing" confusion |
| 27 | Package layering | `StoryService` fetches settings via `TTSSettingsService`; composes the final text (including optional prefix); runs the rune-count check; passes `tts.Options` into `tts.Service.GenerateSpeech`. **`internal/tts` receives the already-composed text, knows nothing about prefixes, settings rows, or `models`.** | Prevents the cycle `tts → services` and keeps the HTTP client thin |
| 28 | Text-length validation | At TTS-call time only (not at story create/update). `utf8.RuneCountInString(finalText) ≤ model_char_limit` — v3=5000, multilingual_v2=10000, flash_v2_5=40000. Returns 422 on overflow. **Rune count, not byte count** — Dutch text contains multi-byte runes (é, ë, ï) where `len()` over-counts | Storage stays unconstrained; only the path that actually calls ElevenLabs blocks |
| 29 | `use_speaker_boost` on v3 | Server **omits the field from the `voice_settings` object** when `model == "eleven_v3"`. DB value preserved | ElevenLabs docs: "Speaker Boost is not available for Eleven v3" |
| 30 | Speed range | **0.7–1.2** (matches ElevenLabs help-docs + Agents Platform; conservative — DB widening later is a simple `ALTER TABLE` without data conflict, while narrowing later would break stored values) | Source conflict between REST API reference (0.25–4.0) and product/help docs (0.7–1.2); we side with the docs that exist for our use case |
| 31 | Migration numbering | New file `migrations/005_tts_settings.sql` (002–004 already exist) | Verified against actual `migrations/` contents |
| 32 | Missing-schema behavior | **New `repository.ErrSchemaUnavailable` sentinel** triggered on MySQL error 1146 (ER_NO_SUCH_TABLE) AND `gorm.ErrRecordNotFound` on `tts_settings`. Service layer wraps both into a new `apperrors.NotInitializedError`. Handler returns **503 Service Unavailable** with a Problem Details body that names the missing migration. Applies to **GET `/settings/tts`, PATCH `/settings/tts`, AND POST `/stories/{id}/tts`** — both `Get` and `Update` go through the same translation | Loud, actionable failure mode on every endpoint regardless of which init step was skipped |
| 33 | Seed determinism wording | Documented as **best-effort, not guaranteed** | ElevenLabs explicitly says so; tests must never assert byte-identical audio |
| 34 | DTO location | `TTSSettings` GORM model lives in `internal/models/tts_settings.go` (no `utils` imports). PATCH request DTO (`TTSSettingsUpdateRequest` with pointers + `utils.Optional[int64]` for `seed`) lives in `internal/utils/http.go` next to `StoryCreateRequest` / `StoryUpdateRequest` | Avoids the `models → utils` import cycle (since `utils → models` already exists at `internal/utils/http.go:21`) |

---

## 3. ElevenLabs research findings (2026)

### `voice_settings` parameters

| Field | Type | API range | Our cap | EL default | Notes |
|-------|------|-----------|---------|------------|-------|
| `stability` | float | 0–1 | 0–1 | 0.5 | In v3 mapped internally to Creative/Natural/Robust modes |
| `similarity_boost` | float | 0–1 | 0–1 | 0.75 | Slightly increases latency |
| `style` | float | 0–1 | 0–1 | 0.0 | v2+ and v3 only; Flash ignores |
| `speed` | float | **0.25–4.0** (REST API ref) / **0.7–1.2** (help-docs + Agents Platform) | **0.7–1.2** | 1.0 | Source conflict — we side with help-docs / Agents Platform |
| `use_speaker_boost` | bool | — | — | true | **Not available on Eleven v3** — server omits the field there |

### Additional body parameters in scope

- `seed` (int, 0–4 294 967 295) — **best-effort** deterministic output when set; null = random. Tests must never assert byte-identical audio.
- `apply_text_normalization` (`auto` / `on` / `off`) — controls how numbers/dates/abbreviations are spoken.

### Models in our whitelist (3 entries)

| `model_id` | Status | Char limit | Audio tags | `use_speaker_boost` |
|---|---|---|---|---|
| `eleven_v3` | GA | **5 000** | Yes | No (server omits) |
| `eleven_multilingual_v2` | GA | 10 000 | No | Yes |
| `eleven_flash_v2_5` | GA — ultra-low latency (~75 ms) | 40 000 | No | Yes (Flash ignores parts of `voice_settings`) |

`eleven_turbo_v2_5` is **not** in the whitelist — ElevenLabs marks it deprecated/outclassed.

### Audio tags pitfall

On v2 and flash, an `[news anchor]` prefix is read literally. That's why **`StoryService`** only includes `tts_style_prefix` in the composed text when `model == "eleven_v3"`. On other models the prefix is silently dropped at compose time; the DB value is preserved either way.

---

## 4. Database

### Migration file: `migrations/005_tts_settings.sql`

```sql
CREATE TABLE IF NOT EXISTS tts_settings (
    id                       INT             NOT NULL,
    model                    VARCHAR(64)     NOT NULL,
    stability                DECIMAL(3,2)    NOT NULL,
    similarity_boost         DECIMAL(3,2)    NOT NULL,
    style                    DECIMAL(3,2)    NOT NULL,
    use_speaker_boost        BOOLEAN         NOT NULL,
    speed                    DECIMAL(3,2)    NOT NULL,
    apply_text_normalization VARCHAR(8)      NOT NULL,
    seed                     BIGINT UNSIGNED NULL,
    tts_style_prefix         VARCHAR(500)    NOT NULL,
    updated_at               TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                             ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_tts_settings_singleton          CHECK (id = 1),
    CONSTRAINT chk_tts_settings_stability          CHECK (stability        >= 0    AND stability        <= 1),
    CONSTRAINT chk_tts_settings_similarity         CHECK (similarity_boost >= 0    AND similarity_boost <= 1),
    CONSTRAINT chk_tts_settings_style              CHECK (style            >= 0    AND style            <= 1),
    CONSTRAINT chk_tts_settings_speed              CHECK (speed            >= 0.7  AND speed            <= 1.2),
    CONSTRAINT chk_tts_settings_text_normalization CHECK (apply_text_normalization IN ('auto', 'on', 'off')),
    CONSTRAINT chk_tts_settings_model              CHECK (model IN (
        'eleven_v3',
        'eleven_multilingual_v2',
        'eleven_flash_v2_5'
    ))
);

INSERT INTO tts_settings (
    id, model, stability, similarity_boost, style, use_speaker_boost,
    speed, apply_text_normalization, seed, tts_style_prefix
) VALUES (
    1, 'eleven_v3', 0.80, 0.80, 0.25, TRUE,
    1.00, 'auto', NULL, '[professional][news anchor][engaging]'
)
ON DUPLICATE KEY UPDATE id = id;
```

### Also incorporate into `migrations/001_complete_schema.sql`

001 has a "drop everything → create fresh" structure: lines 5-14 drop all existing tables inside `SET FOREIGN_KEY_CHECKS=0/1`, then plain `CREATE TABLE` (not `CREATE TABLE IF NOT EXISTS`) recreates them. Two edits are needed in 001:

1. **Drop section** — add `DROP TABLE IF EXISTS tts_settings;` to the block at the top (placement doesn't matter inside the FK-checks-off section, but for tidiness add it adjacent to similarly-leaf tables like `voices`).
2. **Create + seed** — at the bottom, append the table block, but written as plain `CREATE TABLE tts_settings (...)` (no `IF NOT EXISTS`) to stay consistent with the rest of 001, followed by the same `INSERT … ON DUPLICATE KEY UPDATE id = id;` seed.

The standalone `migrations/005_tts_settings.sql` keeps `CREATE TABLE IF NOT EXISTS` because incremental migrations may be re-run on existing deploys. The two files diverge on this single keyword by design.

Result: fresh `docker-compose up -d` (loads 001 via `docker-entrypoint-initdb.d`) and `make db-reset` (`Makefile:132`) both get a clean tts_settings table with the seed row, even after a prior run.

### No runtime seed in Go

The Go binary does **not** run any migration logic and does **not** issue an idempotent `INSERT IGNORE` at boot. Existing deploys MUST apply `005_tts_settings.sql` manually (same workflow as 002–004). If they don't, the missing-schema path described in §5 fires.

### Singleton enforcement

- DB-level: `CHECK (id = 1)` rejects any insert with `id != 1`.
- App-level: `Get(ctx)` uses `WHERE id = 1 LIMIT 1`; `Update(ctx)` updates `WHERE id = 1`. No `Create` / `Delete` methods exposed.

---

## 5. Server behavior

### Package layering (locked)

```
internal/api/handlers/stories.go
   │  calls
   ▼
internal/services/story_service.go
   │  reads settings via                   composes finalText           passes tts.Options ─►  internal/tts/elevenlabs.go
   │       ▼                                       │                          (text, voiceID,            │
   │  internal/services/tts_settings_service.go    │                           options struct)           │ pure HTTP client.
   │       ▼                                       │                                                    │ Marshals body. Zero
   │  internal/repository/tts_settings_repo.go ──► DB                                                    │ knowledge of prefix,
   │                                                                                                    │ settings, models.
   ▼
ElevenLabs API
```

Hard rules:
- `internal/tts` imports only stdlib + `internal/config`. Zero DB, zero services, zero models.
- `tts.Options` carries: `Model string`, `VoiceSettings` (stability/similarity_boost/style/speed + conditionally `UseSpeakerBoost`), `ApplyTextNormalization string`, `Seed *uint32`. **No `Prefix` field. No "prefix applied" flag.**
- `tts.Service.GenerateSpeech(ctx, text, voiceID, opts)` receives the already-composed text and marshals the request body verbatim.
- `StoryService.GenerateStoryAudio` (or equivalent):
  1. Fetches `TTSSettingsService.Get(ctx)` → either `Settings`, `apperrors.NotInitializedError`, or another error.
  2. Composes `finalText`:
     ```go
     finalText := story.Text
     if settings.Model == "eleven_v3" && strings.TrimSpace(settings.TTSStylePrefix) != "" {
         finalText = settings.TTSStylePrefix + "\n" + story.Text
     }
     ```
  3. Runs the rune-count cap and emits a 422-bound error (see "Service-layer 422 plumbing" below):
     ```go
     if utf8.RuneCountInString(finalText) > modelCharLimit(settings.Model) {
         return apperrors.NewValidationProblemError(
             "story",
             "Text too long for selected TTS model",
             []apperrors.FieldValidationError{{
                 Field:   "text",
                 Message: fmt.Sprintf("rune count %d exceeds limit %d for model %s",
                     utf8.RuneCountInString(finalText),
                     modelCharLimit(settings.Model),
                     settings.Model),
             }},
         )
     }
     ```
  4. Builds `tts.Options` (without `UseSpeakerBoost` field set when `settings.Model == "eleven_v3"`).
  5. Calls `tts.Service.GenerateSpeech(ctx, finalText, voice.ElevenLabsVoiceID, opts)`.

### Read-on-every-call

`StoryService` reads the current settings row from DB per TTS request. No in-memory cache, no TTL, no invalidation.

### Building the ElevenLabs request body (inside `internal/tts`)

```jsonc
// Example body emitted by tts.Service.GenerateSpeech for POST /v1/text-to-speech/{voice_id}
{
  "text":     "<finalText, already composed by StoryService>",
  "model_id": "<opts.Model>",
  "voice_settings": {
    "stability":         <opts.VoiceSettings.Stability>,
    "similarity_boost":  <opts.VoiceSettings.SimilarityBoost>,
    "style":             <opts.VoiceSettings.Style>,
    "speed":             <opts.VoiceSettings.Speed>
    // "use_speaker_boost" omitted entirely when StoryService didn't set it
  },
  "apply_text_normalization": "<opts.ApplyTextNormalization>"
  // "seed" omitted entirely when opts.Seed == nil
}
```

Rules (`internal/tts` only):
- Marshal what's in `opts`. Nothing else.
- `opts.Seed` is `*uint32`. When nil → field omitted from body.
- `opts.VoiceSettings.UseSpeakerBoost` is `*bool`. When nil → field omitted from `voice_settings`.
- No conditional logic on `model_id` inside `internal/tts`. All model-aware decisions (prefix, speaker_boost omission) are made by `StoryService` *before* calling `GenerateSpeech`.

### Text-length validation (at TTS-call time, server-side)

Inside `StoryService`, after composing `finalText`:

| `settings.model` | `utf8.RuneCountInString(finalText) ≤` |
|---|---|
| `eleven_v3` | 5 000 |
| `eleven_multilingual_v2` | 10 000 |
| `eleven_flash_v2_5` | 40 000 |

On overflow: 422 via `utils.ProblemValidationError` with a single `errors[]` entry on field `text`. The story create/update endpoints stay unbounded.

The newline between prefix and text is automatically included in `finalText` (when applied), so the rune count is exact — no extra `+1` arithmetic in the check.

### Service-layer 422 plumbing (NEW typed error)

`*apperrors.ValidationError` (the existing single-field error) is mapped to **400** by `handleServiceError` — it cannot be reused for our 422 path. So we add a second typed error specifically for multi-field, 422-bound validation:

```go
// internal/apperrors/errors.go (new section)

// FieldValidationError mirrors utils.ValidationError but lives in apperrors so
// the apperrors package keeps zero dependencies on internal/utils.
type FieldValidationError struct {
    Field   string
    Message string
}

// ValidationProblemError aggregates multiple per-field validation failures and
// is mapped to HTTP 422 by handleServiceError via utils.ProblemValidationError.
// Resource is what handleServiceError uses for structured logging — matches the
// pattern of the existing *ValidationError type which also carries Resource.
type ValidationProblemError struct {
    Resource string
    Detail   string
    Errors   []FieldValidationError
}

func (e *ValidationProblemError) Error() string {
    return e.Detail
}

func (e *ValidationProblemError) Unwrap() error { return nil }

// NewValidationProblemError constructs the typed error.
func NewValidationProblemError(resource, detail string, errs []FieldValidationError) *ValidationProblemError {
    return &ValidationProblemError{Resource: resource, Detail: detail, Errors: errs}
}
```

`handleServiceError` gains a new case (added **before** the existing `*apperrors.ValidationError` case so it takes priority). It uses `vp.Resource` for logging — not a hardcoded string — because this same error type is returned by both `TTSSettingsService` (resource = `"tts_settings"`) and `StoryService` (resource = `"story"`, on text-length overflow):

```go
if vp, ok := errors.AsType[*apperrors.ValidationProblemError](err); ok {
    logError(strings.ToLower(vp.Resource), "validation_failed", err)
    utilsErrs := make([]utils.ValidationError, 0, len(vp.Errors))
    for _, e := range vp.Errors {
        utilsErrs = append(utilsErrs, utils.ValidationError{Field: e.Field, Message: e.Message})
    }
    utils.ProblemValidationError(c, vp.Detail, utilsErrs)
    return
}
```

Both PATCH /settings/tts validation (range/enum/prefix-length checks) and the StoryService text-length cap use this single path. Empty-body validation stays in the handler — see §6 "PATCH body".

### Validation (422 + Problem Details, RFC 9457)

PATCH `/api/v1/settings/tts` validates via the new `apperrors.ValidationProblemError` → `handleServiceError` → `utils.ProblemValidationError`. Rejected inputs:

- `model` not in the enum (`eleven_v3`, `eleven_multilingual_v2`, `eleven_flash_v2_5`).
- Any 0–1 float out of `[0, 1]`.
- `speed` out of `[0.7, 1.2]`.
- `apply_text_normalization` not in `{auto, on, off}`.
- `seed` outside `[0, 4 294 967 295]` (when not null).
- `tts_style_prefix` runes-count > 500.

Each invalid field produces an entry in `errors[]` with `{ field, message }`. Response title is fixed `"Validation Error"`; type is fixed `https://babbel.api/problems/validation-error`; status is 422. No `code` field on `ValidationError` (matches existing `internal/utils/problems.go:44-48`).

### Missing-schema / missing-row → 503

Two error paths produce the same 503 response. **Both `Get(ctx)` and `Update(ctx, ...)` go through this path** — meaning GET `/settings/tts`, PATCH `/settings/tts`, and POST `/stories/{id}/tts` all return 503 when the table or row is missing. `Update` calls `Get` internally first (or wraps a 0-rows-affected outcome) to detect the missing-row case before attempting the UPDATE.

1. MySQL error 1146 (`ER_NO_SUCH_TABLE`) when the `tts_settings` table doesn't exist.
2. `gorm.ErrRecordNotFound` from `Get(ctx)` when the row is missing.

Implementation:

- `internal/repository/errors.go` gets a new sentinel:
  ```go
  // ErrSchemaUnavailable indicates a referenced table is missing — typically a forgotten migration.
  var ErrSchemaUnavailable = errors.New("schema unavailable")
  ```
  `ParseDBError` adds a case for MySQL error 1146 returning `ErrSchemaUnavailable`.

- `internal/apperrors/errors.go` gets a new typed error **with an explicit `Error()` method and `Unwrap()`** so it satisfies the `error` interface (required for `errors.AsType[*apperrors.NotInitializedError]` to work):
  ```go
  // NotInitializedError indicates a required resource is not initialized (typically a missing migration).
  type NotInitializedError struct {
      Resource string
      Hint     string
      cause    error
  }

  func (e *NotInitializedError) Error() string {
      return fmt.Sprintf("%s not initialized", e.Resource)
  }

  func (e *NotInitializedError) Unwrap() error { return e.cause }

  // NotInitialized creates a NotInitializedError for the given resource and remediation hint.
  func NotInitialized(resource, hint string, cause error) *NotInitializedError {
      return &NotInitializedError{Resource: resource, Hint: hint, cause: cause}
  }
  ```
- `TTSSettingsService.Get(ctx)` translates `repository.ErrSchemaUnavailable` AND `repository.ErrNotFound` (on tts_settings) into `apperrors.NotInitialized("tts_settings", "apply migration 005_tts_settings.sql", err)`.
- `TTSSettingsService.Update(ctx, req)` **calls `Get(ctx)` first** to detect missing-table or missing-row before attempting the UPDATE. Reason: the generic `GormRepository[T].UpdateByID` returns `ErrNotFound` when `RowsAffected == 0` (`gorm_base.go:99-101`), but for a singleton an idempotent PATCH (admin submits the same values that are already stored) yields `RowsAffected == 0` — which is a **valid** outcome, not a missing row. So:
  - The settings repo's `Update` is a **custom method** (not `UpdateByID`) that builds the column→value map via `repository.BuildUpdateMap(u)` (`update_helper.go:26`) and passes it to `Updates(map[string]any)` — **not** to `Updates(struct)`. GORM's struct-form Updates silently skips zero-valued fields, but for us `stability=0`, `style=0`, `use_speaker_boost=false`, and `tts_style_prefix=""` are all legitimate PATCH values an admin may want to set. The map form sets them faithfully. Pattern matches `voice_repository.go:56-61`.

    For `BuildUpdateMap` to produce the correct column names, the repo-level update struct MUST carry `gorm:"column:..."` tags on every updatable field. Without the tag, `update_helper.go:138-147 toSnakeCase` is used as fallback — fine for `Stability` → `stability`, but **wrong** for acronym-heavy field names: `TTSStylePrefix` falls back to `t_t_s_style_prefix`, not `tts_style_prefix`. Always tag explicitly. Clear-flags carry `gorm:"-"` per project convention (see `VoiceUpdate`, `StoryUpdate`); they're skipped from the map either way (by the `Clear*` name prefix at `update_helper.go:83-85`), but the tag documents intent.

    ```go
    // internal/repository/tts_settings_repo.go

    // TTSSettingsUpdate contains optional fields for updating the singleton TTS settings.
    // Nil pointer fields are not updated. Clear* flags explicitly set fields to NULL.
    type TTSSettingsUpdate struct {
        Model                  *string  `gorm:"column:model"`
        Stability              *float64 `gorm:"column:stability"`
        SimilarityBoost        *float64 `gorm:"column:similarity_boost"`
        Style                  *float64 `gorm:"column:style"`
        UseSpeakerBoost        *bool    `gorm:"column:use_speaker_boost"`
        Speed                  *float64 `gorm:"column:speed"`
        ApplyTextNormalization *string  `gorm:"column:apply_text_normalization"`
        Seed                   *int64   `gorm:"column:seed"`
        TTSStylePrefix         *string  `gorm:"column:tts_style_prefix"` // explicit column name — acronym would mis-snake-case

        // Clear flags - when true, explicitly set the field to NULL
        ClearSeed bool `gorm:"-"`
    }

    func (r *TTSSettingsRepo) Update(ctx context.Context, u *TTSSettingsUpdate) error {
        if u == nil { return nil }
        updateMap := repository.BuildUpdateMap(u)
        if len(updateMap) == 0 { return nil }

        db := repository.DBFromContext(ctx, r.db)
        result := db.WithContext(ctx).
            Model(&models.TTSSettings{}).
            Where("id = ?", 1).
            Updates(updateMap)
        if result.Error != nil { return repository.ParseDBError(result.Error) }
        // RowsAffected==0 is success here: same-value PATCH is valid for a singleton.
        return nil
    }
    ```
  - The service `Get`-before-`Update` provides the actual missing-row detection. If `Get` succeeds, `Update` cannot meaningfully fail with "row missing".
  - This avoids a false 503 on no-op same-value PATCHes **and** correctly persists zero-valued updates.
- `internal/api/handlers/base.go handleServiceError` adds a case (using the existing `ProblemExtended` pattern):
  ```go
  if ni, ok := errors.AsType[*apperrors.NotInitializedError](err); ok {
      logError(ni.Resource, "not_initialized", err)
      utils.ProblemExtended(c, http.StatusServiceUnavailable,
          ni.Error(),
          strings.ToLower(ni.Resource)+".not_initialized",
          ni.Hint,
      )
      return
  }
  ```

GET `/api/v1/settings/tts`, PATCH `/api/v1/settings/tts`, and POST `/api/v1/stories/{id}/tts` all go through this path.

### Concurrency

Last-write-wins. No `If-Match`. Mirrors every other PATCH handler in the codebase.

### Audit

```go
import "github.com/oszuidwest/zwfm-babbel/pkg/logger"

logger.Info("tts settings updated",
    "user_id",        userID,
    "changed_fields", changed,
    "new_model",      newSettings.Model,
    // … new values only for the fields that actually changed
)
```

Uses `pkg/logger` (the project's slog wrapper). **Not** raw `slog.Info` — `internal/` has zero direct `slog.X` call sites.

No DB audit table. No `updated_by` column.

---

## 6. REST API

### Endpoints

```
GET   /api/v1/settings/tts   — admin + editor + viewer  (settings:tts read)
PATCH /api/v1/settings/tts   — admin only               (settings:tts write)
```

### Permissions

`internal/auth/permissions.go` gets:
```go
const ResourceSettingsTTS Resource = "settings:tts"
```

`internal/auth/service.go:initializeRBAC` adds the four policy lines inline:
```
p, admin,  settings:tts, read
p, admin,  settings:tts, write
p, editor, settings:tts, read
p, viewer, settings:tts, read
```

No CSV file exists in this project — policies are added via `enforcer.AddPolicy(...)`.

### GET response (200)

```json
{
  "model": "eleven_v3",
  "stability": 0.80,
  "similarity_boost": 0.80,
  "style": 0.25,
  "use_speaker_boost": true,
  "speed": 1.00,
  "apply_text_normalization": "auto",
  "seed": null,
  "tts_style_prefix": "[professional][news anchor][engaging]",
  "updated_at": "2026-06-06T12:34:56Z",
  "api_key_configured": true
}
```

`api_key_configured` reflects whether `BABBEL_ELEVENLABS_API_KEY` is non-empty in env. Never returns the value itself.

### PATCH body — partial update

```json
{
  "stability": 0.7,
  "seed": null
}
```

Two request DTOs follow the existing `voices.go:64-89` pattern. **The mapper lives in the handler package** — putting it on the utils DTO would force `utils → services`, but `services → utils` already exists (`services/story_service.go:19`, `services/station_voice_service.go:14`, `services/bulletin_service.go:15`) → cycle. Handlers may import both packages, so the mapping happens there.

1. `utils.TTSSettingsUpdateRequest` (in `internal/utils/http.go`) — pointers for primitives, `utils.Optional[int64]` for `seed` (distinguishes absent / null / value, matches `internal/utils/optional.go`). Used by the handler for JSON binding.
2. `services.UpdateTTSSettingsRequest` (in `internal/services/tts_settings_service.go`) — service-level struct with the same fields plus `ClearSeed bool`.
3. `toTTSSettingsServiceRequest(req utils.TTSSettingsUpdateRequest) *services.UpdateTTSSettingsRequest` — free function in `internal/api/handlers/tts_settings.go`. Translates `Optional[int64]` into either `Seed *int64` (when set+non-null) or `ClearSeed=true` (when set+null).

Handler flow (matches `voices.go:64-94`):

```go
func (h *Handlers) UpdateTTSSettings(c *gin.Context) {
    var req utils.TTSSettingsUpdateRequest
    if !utils.BindAndValidate(c, &req) { return }

    // Empty JSON object check at handler level (same as voices.go:69-76).
    // Note: a truly empty body (zero bytes) already fails at utils.BindAndValidate's
    // json.Decode step (utils/http.go:275) with "Invalid request format". This
    // IsEmpty() guard only fires when the body parses to a JSON object like `{}`
    // with no fields set.
    if req.IsEmpty() {
        utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
            Field:   "request",
            Message: "At least one field must be provided",
        }})
        return
    }

    serviceReq := toTTSSettingsServiceRequest(req)  // free function, handler-local
    updated, err := h.ttsSettingsSvc.Update(c.Request.Context(), serviceReq)
    if err != nil {
        handleServiceError(c, err, "TTSSettings")  // 503 if NotInitialized, 422 if ValidationProblem, etc.
        return
    }
    utils.Success(c, updated)
}
```

Returns the full updated resource (same shape as GET).

Range/enum/length validation (stability ∈ [0,1], speed ∈ [0.7,1.2], model ∈ enum, prefix ≤ 500 runes, etc.) happens **inside `TTSSettingsService.Update`**, which aggregates failures into a single `apperrors.NewValidationProblemError("tts_settings", "Validation failed", errs)` returned to `handleServiceError` → 422.

### Error responses

422 validation error (e.g. PATCH with `stability=1.5` and `tts_style_prefix` too long):

```json
{
  "type":      "https://babbel.api/problems/validation-error",
  "title":     "Validation Error",
  "status":    422,
  "detail":    "One or more fields failed validation",
  "instance":  "/api/v1/settings/tts",
  "timestamp": "2026-06-06T12:34:56Z",
  "errors": [
    { "field": "stability",        "message": "must be between 0 and 1" },
    { "field": "tts_style_prefix", "message": "must be at most 500 characters" }
  ]
}
```

503 missing-schema (table missing OR row missing) — on GET `/settings/tts`, PATCH `/settings/tts`, AND POST `/stories/{id}/tts`. The body is what `utils.ProblemExtended(c, 503, "tts_settings not initialized", "tts_settings.not_initialized", "apply migration 005_tts_settings.sql")` produces verbatim:

```json
{
  "type":      "https://babbel.api/problems/tts_settings.not_initialized",
  "title":     "Service Unavailable",
  "status":    503,
  "detail":    "tts_settings not initialized",
  "instance":  "/api/v1/settings/tts",
  "timestamp": "2026-06-06T12:34:56Z",
  "code":      "tts_settings.not_initialized",
  "hint":      "apply migration 005_tts_settings.sql"
}
```

Notes:
- `type` is `"https://babbel.api/problems/" + code` per `responses.go:164` — so the code value becomes the URL path component.
- `title` is `http.StatusText(503)` per `responses.go:165` — `"Service Unavailable"`.
- `code` and `hint` are populated by `ProblemExtended` itself (`responses.go:170-171`).
- No `ProblemTypeServiceUnavailable` constant in `internal/utils/problems.go` is needed — `ProblemExtended` derives the type from `code`.

---

## 7. Code impact (file-by-file)

| Path | Change |
|------|--------|
| `migrations/005_tts_settings.sql` | New — `CREATE TABLE` + seed row (speed CHECK: 0.7–1.2) |
| `migrations/001_complete_schema.sql` | **Two edits**: (a) add `DROP TABLE IF EXISTS tts_settings;` to the drop section at `001:5-14`; (b) append the table block (using plain `CREATE TABLE`, not `IF NOT EXISTS`, to match the rest of 001) + the `INSERT … ON DUPLICATE KEY UPDATE id = id` seed at the bottom. Required so `make db-reset` rebuilds the singleton from scratch. |
| `internal/models/tts_settings.go` | New — **GORM model only**. Zero `utils` imports. |
| `internal/utils/http.go` | Add `TTSSettingsUpdateRequest` DTO (pointers + `utils.Optional[int64]` for `seed`) + an `IsEmpty()` method covering all fields. Place near the existing `StoryUpdateRequest`. |
| `internal/repository/errors.go` | Add `ErrSchemaUnavailable`; extend `ParseDBError` with MySQL error 1146 case |
| `internal/repository/tts_settings_repo.go` | New — singleton-aware repo. Also defines the repo-level `TTSSettingsUpdate` struct (with `gorm:"column:..."` tags + `Clear*` flags), mirroring how `repository.VoiceUpdate` lives next to `VoiceRepository`. `Get(ctx)` uses `Where("id = ?", 1).First(&row)`. `Update(ctx, u *TTSSettingsUpdate)` calls `BuildUpdateMap(u)` (`update_helper.go:26`) to produce `map[string]any`, then `db.Model(&TTSSettings{}).Where("id = ?", 1).Updates(updateMap)`. **Critical**: the map form, not the struct form — GORM's `Updates(struct)` skips zero values, which would lose legitimate PATCHes like `stability=0` or `use_speaker_boost=false`. Ignores `RowsAffected` so idempotent same-value PATCHes succeed. Does NOT delegate to `GormRepository[T].UpdateByID`. No Create/Delete exposed. |
| `internal/apperrors/errors.go` | Add **two** new typed errors: `NotInitializedError` (with `Error()`/`Unwrap()`) and `ValidationProblemError` + `FieldValidationError` (with `Error()`/`Unwrap()`). `ValidationProblemError` has a `Resource` field so the handler logs the correct resource regardless of caller (settings service OR story service). Factory functions `NotInitialized(...)` and `NewValidationProblemError(resource, detail, errs)` |
| `internal/services/tts_settings_service.go` | New — defines its own `UpdateTTSSettingsRequest` struct (with `Clear*` flags) at the service layer. `Get(ctx)` and `Update(ctx, *UpdateTTSSettingsRequest)`. **`Update` calls `Get` first** to detect missing-table/row, then translates the service-DTO → `repository.TTSSettingsUpdate` (mirrors `voice_service.go:64-68`), then calls the custom repo `Update` (whose 0-rows-affected outcome is treated as success, since same-value PATCH is valid). Both `Get` and the preliminary `Get` inside `Update` map `repository.ErrSchemaUnavailable` and `repository.ErrNotFound` to `apperrors.NotInitializedError` — so PATCH returns 503 when uninitialized. Range/enum/length validation in `Update` aggregates into `apperrors.NewValidationProblemError("tts_settings", ...)`. `pkg/logger.Info` audit. |
| `internal/services/story_service.go` | Inject `TTSSettingsService`. Fetch settings, compose `finalText` (prefix only when `model == "eleven_v3"`), run `utf8.RuneCountInString` cap check, build `tts.Options`, call `tts.Service.GenerateSpeech`. |
| `internal/api/handlers/tts_settings.go` | New — `GET`/`PATCH` handlers + the free function `toTTSSettingsServiceRequest(utils.TTSSettingsUpdateRequest) *services.UpdateTTSSettingsRequest` (lives here to avoid the `utils → services` cycle). PATCH does the empty-object check (`req.IsEmpty()` → 422 directly via `utils.ProblemValidationError`, matching `voices.go:69-76`), then maps and delegates. GET adds `api_key_configured` to response. |
| `internal/api/handlers/base.go` | Extend `handleServiceError` with **two** new cases: (a) `*apperrors.ValidationProblemError` → `utils.ProblemValidationError` (422), placed **before** the existing `*apperrors.ValidationError` case; (b) `*apperrors.NotInitializedError` → `utils.ProblemExtended(c, 503, …)` |
| `internal/api/router.go` (or wherever routes live) | Add the two routes with RBAC middleware |
| `internal/auth/permissions.go` | Add `ResourceSettingsTTS` constant |
| `internal/auth/service.go` | Extend `initializeRBAC()` with the four policy lines |
| `internal/tts/elevenlabs.go` | Add `tts.Options` struct (Model, VoiceSettings, ApplyTextNormalization, Seed). `GenerateSpeech` signature gains `opts Options`. Body-build marshals verbatim — no model-conditional logic, no prefix logic. `UseSpeakerBoost` and `Seed` are pointer fields, omitted when nil. |
| `internal/config/config.go` | Remove `Model` field from `TTSConfig` (keep `APIKey`, `RequestTimeout`) |
| `cmd/babbel/main.go` (or wherever wiring lives) | Inject `TTSSettingsService` into `StoryService` |
| `openapi.yaml` | New paths `/settings/tts`, schemas `TTSSettings` + `TTSSettingsUpdate`, the 422 + 503 problem responses |
| `tests/settings/tts-settings.test.js` | New — hand-written Jest suite. **Captures the original singleton row in `beforeAll` via GET, restores it in `afterAll` via PATCH** (matches the project's max-workers=1 + shared-DB-state model — any test that mutates global config must restore). Cases: GET ok / PATCH partial / PATCH `seed: null` / PATCH `{}` → 422 `{field: "request", message: "At least one field must be provided"}` / PATCH with zero-byte body → 422 `{field: "request", message: "Invalid request format"}` (decoded by `BindAndValidate` before reaching the IsEmpty guard) / PATCH idempotent same-value → 200 (verifies the custom repo's `RowsAffected==0`-is-success behavior) / PATCH out-of-range → 422 `errors[]` matching real shape (field + message only) / PATCH prefix > 500 runes / RBAC admin / editor / viewer / unauthenticated / `api_key_configured` reflects env / OpenAPI contract scenario |
| `tests/jest.testSequencer.js` | Insert `settings` **after** `tts` in the ordered list (so tts.test.js sees the seeded singleton row unchanged before settings.test.js mutates it; the afterAll-restore is a safety net but ordering still helps) |
| `tests/openapi/openapi-contract.test.js` | Add two scenarios: `GET /api/v1/settings/tts` and `PATCH /api/v1/settings/tts`. The PATCH scenario is **self-restoring**: it first GETs the current row, then PATCHes with a single field (e.g. `{ stability: <current.stability> }`) so the singleton state is preserved across the suite. This works precisely because the singleton repo treats `RowsAffected == 0` as success (§5 RowsAffected note). The settings-suite's `afterAll` restore is gone by the time the contract suite runs — self-restore is the safety net. |
| `.env.example` | Remove `BABBEL_ELEVENLABS_MODEL` |
| `CLAUDE.md` | New short subsection under "Architecture" describing `tts_settings` singleton, read-on-every-call, the layering rule (StoryService owns settings + composition; tts package stays a marshaller), and the rune-count cap |
| `docs/` regen | `make docs-all` |

### Out of scope (explicit non-goals)

- No frontend code (separate repo).
- No `output_format` setting.
- No API-key UI editing.
- No `MaxAttempts` / alignment retry.
- No OpenWeather / OpenAI / scheduler / rotation / review UI integration.
- No per-station settings.
- No per-call query/body overrides on `POST /stories/{id}/tts`.
- No audit table or `updated_by` column.
- No optimistic locking / `If-Match`.
- No per-story settings snapshot.
- No `language_code` field.
- No `eleven_turbo_v2_5` in the model whitelist.
- No runtime-seed / `AutoMigrate` / migration runner.
- No length cap on `Story.Text` at create/update time — only at TTS-call time.
- No chunking for stories longer than the model character limit.
- No `code` field on `ValidationError` — conform to existing shape.

---

## 8. Open questions

None at the time of writing. If a follow-up needs:
- `language_code` (Dutch mis-detected as German on multilingual_v2) → single nullable column, same pattern as `seed`.
- Widening `speed` to 0.25–4.0 → simple `ALTER TABLE … DROP CONSTRAINT chk_tts_settings_speed; ADD CONSTRAINT … CHECK (0.25, 4.0)` (no data conflict, since stored values are inside the wider range).
- `ProblemTypeServiceUnavailable` constant in `internal/utils/problems.go` — not needed for this feature (`ProblemExtended` derives the type from `code`), but could be added if another endpoint later wants a stable named URI.

---

## 9. Sources

- ElevenLabs `voice_settings` reference (official skills repo) — <https://github.com/elevenlabs/skills/blob/main/text-to-speech/references/voice-settings.md>
- ElevenLabs Text to Speech API reference — <https://elevenlabs.io/docs/api-reference/text-to-speech/convert>
- ElevenLabs default voice settings — <https://elevenlabs.io/docs/api-reference/voices/settings/get-default>
- ElevenLabs Models overview (status, character limits) — <https://elevenlabs.io/docs/overview/models>
- ElevenLabs Speed control (Agents Platform 0.7–1.2) — <https://elevenlabs.io/docs/agents-platform/customization/voice/speed-control>
- ElevenLabs Speed help article — <https://help.elevenlabs.io/hc/en-us/articles/13416271012497-Can-I-change-the-pace-of-the-voice>
- ElevenLabs character limit help — <https://help.elevenlabs.io/hc/en-us/articles/13298164480913-What-s-the-maximum-amount-of-characters-and-text-I-can-generate>
- `babbel-ai-gen` source — <https://github.com/oszuidwest/babbel-ai-gen>
