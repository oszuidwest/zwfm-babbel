// Module-level flags: determine which describe blocks run/skip.
// Using env vars (not runtime probes) so describe.skip works at definition time.
const TTS_ENABLED = process.env.BABBEL_TEST_TTS_ENABLED === 'true';
const TTS_REAL_API = process.env.BABBEL_TEST_TTS_REAL_API === 'true';
const ELEVENLABS_VOICE_ID = process.env.BABBEL_TEST_ELEVENLABS_VOICE_ID || null;

const NONEXISTENT_STORY_ID = 2147483647;

describe('TTS', () => {
  const createVoice = async (baseName, elevenLabsVoiceId = null) => {
    const payload = { name: global.helpers.uniqueName(baseName) };
    if (elevenLabsVoiceId) {
      payload.elevenlabs_voice_id = elevenLabsVoiceId;
    }

    const response = await global.api.apiCall('POST', '/voices', payload);
    global.helpers.fixtureResponse(response, 'POST', '/voices');

    global.resources.track('voices', response.data.id);
    return response.data.id;
  };

  const createStory = async (title, text, voiceId = null) => {
    const result = await global.helpers.createStory(global.resources, {
      title,
      text,
      voice_id: voiceId,
      status: 'active',
      weekdays: 127
    });

    return result.id;
  };

  const uploadTestAudio = async (storyId) => {
    const audioPath = `/tmp/tts_test_audio_${Date.now()}.wav`;
    try {
      global.helpers.createTestAudioFile(audioPath, 1);
      const response = await global.api.uploadFile(
        `/stories/${storyId}/audio`, {}, audioPath, 'audio'
      );
      global.helpers.fixtureResponse(response, 'POST', `/stories/${storyId}/audio`, 201, false);
    } finally {
      global.helpers.cleanupTempFile(audioPath);
    }
  };

  (TTS_ENABLED ? describe.skip : describe)('TTS Disabled', () => {
    test('when TTS not configured, then returns 501', async () => {
      const response = await global.api.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

      expect(response.status).toBe(501);
      expect(response.data.type).toContain('tts.not_configured');
    });
  });

  (TTS_ENABLED ? describe : describe.skip)('Validation Chain (requires TTS)', () => {
    test('when story not found, then returns 404', async () => {
      const response = await global.api.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

      expect(response.status).toBe(404);
      expect(response.data.type).toContain('story.not_found');
    });

    test('when story is deleted, then returns 410', async () => {
      const storyId = await createStory('TTS Deleted Story', 'Some text content for TTS');
      expect((await global.api.apiCall('DELETE', `/stories/${storyId}`)).status).toBe(204);

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      expect(response.status).toBe(410);
      expect(response.data.code).toBe('story.deleted');
    });

    test('when story has no voice, then returns 409', async () => {
      const storyId = await createStory('TTS No Voice Story', 'Some text content for TTS');

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      expect(response.status).toBe(409);
      expect(response.data.code).toBe('story.no_voice');
    });

    test('when voice has no ElevenLabs ID, then returns 409', async () => {
      const voiceId = await createVoice('TTS No EL Voice');

      const storyId = await createStory('TTS No EL ID Story', 'Some text content for TTS', voiceId);

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      expect(response.status).toBe(409);
      expect(response.data.code).toBe('voice.no_elevenlabs_id');
    });

    test('when story already has audio without force, then returns 409', async () => {
      expect(global.helpers.isFFmpegAvailable()).toBe(true);

      const voiceId = await createVoice('TTS Audio Exists Voice', 'dummy-el-voice-id');

      const storyId = await createStory('TTS Audio Exists Story', 'Some text content for TTS', voiceId);

      await uploadTestAudio(storyId);

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      expect(response.status).toBe(409);
      expect(response.data.code).toBe('story.audio_exists');
      expect(response.data.hint).toContain('force');
    });
  });

  (TTS_ENABLED && TTS_REAL_API && ELEVENLABS_VOICE_ID ? describe : describe.skip)(
    'Real API (requires TTS + BABBEL_TEST_TTS_REAL_API=true)', () => {
    test('when force overwrite with real API, then returns 201', async () => {
      expect(global.helpers.isFFmpegAvailable()).toBe(true);

      const voiceId = await createVoice('TTS Force Voice', ELEVENLABS_VOICE_ID);

      const storyId = await createStory(
        'TTS Force Overwrite Story',
        'Dit is een test verhaal voor tekst naar spraak.',
        voiceId
      );

      await uploadTestAudio(storyId);

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts?force=true`);

      expect(response.status).toBe(201);
    });

    test('when generating TTS for story without audio, then returns 201', async () => {
      const voiceId = await createVoice('TTS Happy Path Voice', ELEVENLABS_VOICE_ID);

      const storyId = await createStory(
        'TTS Happy Path Story',
        'Dit is een test verhaal voor tekst naar spraak.',
        voiceId
      );

      const beforeResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(beforeResponse.status).toBe(200);

      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      expect(response.status).toBe(201);

      const afterResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(afterResponse.status).toBe(200);
      expect(afterResponse.data.audio_file).toBeTruthy();
      expect(afterResponse.data.audio_url).toBeTruthy();
    });
  });
});
