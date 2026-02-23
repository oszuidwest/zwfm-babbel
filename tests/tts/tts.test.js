/**
 * Babbel TTS (text-to-speech) tests.
 * Tests the POST /api/v1/stories/{id}/tts endpoint validation chain.
 * Adapts to whether TTS is enabled or disabled on the server.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

// ID that should never exist in any realistic database
const NONEXISTENT_STORY_ID = 2147483647;

describe('TTS', () => {
  // TTS mode flags (detected during setup)
  let ttsEnabled = false;
  let ttsRealApi = false;
  let realElevenLabsVoiceId = null;

  // Shared test station (stories require target_stations)
  let testStationId = null;

  // Helper to create a voice with optional ElevenLabs voice ID
  const createVoice = async (baseName, elevenLabsVoiceId = null) => {
    const payload = { name: global.helpers.uniqueName(baseName) };
    if (elevenLabsVoiceId) {
      payload.elevenlabs_voice_id = elevenLabsVoiceId;
    }

    const response = await global.api.apiCall('POST', '/voices', payload);
    if (response.status !== 201 || !response.data?.id) return null;

    global.resources.track('voices', response.data.id);
    return response.data.id;
  };

  // Helper to create a story (without audio) tracked for cleanup
  const createStory = async (title, text, voiceId = null) => {
    const result = await global.helpers.createStory(global.resources, {
      title,
      text,
      voice_id: voiceId,
      status: 'active',
      weekdays: 127
    }, [parseInt(testStationId, 10)]);

    return result ? result.id : null;
  };

  // Helper to upload a short silent audio file to a story
  const uploadTestAudio = async (storyId) => {
    const audioPath = `/tmp/tts_test_audio_${Date.now()}.wav`;
    if (!global.helpers.createTestAudioFile(audioPath, 1)) return false;

    try {
      const response = await global.api.uploadFile(
        `/stories/${storyId}/audio`, {}, audioPath, 'audio'
      );
      return response.status === 201;
    } finally {
      global.helpers.cleanupTempFile(audioPath);
    }
  };

  beforeAll(async () => {
    // Create a station for story dependencies
    const station = await global.helpers.createStation(global.resources, 'TTS Test Station');
    expect(station).not.toBeNull();
    testStationId = station.id;

    // Detect TTS mode by probing the endpoint
    const probe = await global.api.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);
    ttsEnabled = probe.status !== 501;

    ttsRealApi = process.env.BABBEL_TEST_TTS_REAL_API === 'true';
    realElevenLabsVoiceId = process.env.BABBEL_TEST_ELEVENLABS_VOICE_ID || null;

    if (ttsEnabled) {
      console.log('TTS is enabled on this server');
      if (ttsRealApi) {
        console.log(`Real ElevenLabs API tests enabled (voice: ${realElevenLabsVoiceId || 'NOT SET'})`);
      }
    } else {
      console.log('TTS is disabled on this server (no API key configured)');
    }
  });

  describe('TTS Disabled', () => {
    test('when TTS not configured, then returns 501', async () => {
      if (ttsEnabled) return; // This test only applies when TTS is disabled

      // Act
      const response = await global.api.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

      // Assert
      expect(response.status).toBe(501);
      expect(response.data.type).toContain('tts.not_configured');
    });
  });

  describe('Validation Chain (requires TTS)', () => {
    test('when story not found, then returns 404', async () => {
      if (!ttsEnabled) return;

      // Act
      const response = await global.api.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

      // Assert
      expect(response.status).toBe(404);
      expect(response.data.type).toContain('story.not_found');
    });

    test('when story has no voice, then returns 400', async () => {
      if (!ttsEnabled) return;

      // Arrange
      const storyId = await createStory('TTS No Voice Story', 'Some text content for TTS');
      expect(storyId).not.toBeNull();

      // Act
      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      // Assert
      expect(response.status).toBe(400);
      expect(response.data.type).toContain('story.validation_failed');
    });

    test('when voice has no ElevenLabs ID, then returns 400', async () => {
      if (!ttsEnabled) return;

      // Arrange: voice without elevenlabs_voice_id
      const voiceId = await createVoice('TTS No EL Voice');
      expect(voiceId).not.toBeNull();

      const storyId = await createStory('TTS No EL ID Story', 'Some text content for TTS', voiceId);
      expect(storyId).not.toBeNull();

      // Act
      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      // Assert
      expect(response.status).toBe(400);
      expect(response.data.type).toContain('voice.validation_failed');
    });

    test('when story already has audio without force, then returns 400', async () => {
      if (!ttsEnabled) return;
      if (!global.helpers.isFFmpegAvailable()) return;

      // Arrange: voice with dummy elevenlabs ID (won't actually call ElevenLabs)
      const voiceId = await createVoice('TTS Audio Exists Voice', 'dummy-el-voice-id');
      expect(voiceId).not.toBeNull();

      const storyId = await createStory('TTS Audio Exists Story', 'Some text content for TTS', voiceId);
      expect(storyId).not.toBeNull();

      const uploaded = await uploadTestAudio(storyId);
      expect(uploaded).toBe(true);

      // Act
      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      // Assert
      expect(response.status).toBe(400);
      expect(response.data.type).toContain('story.validation_failed');
      expect(response.data.detail).toContain('force');
    });
  });

  describe('Real API (requires TTS + BABBEL_TEST_TTS_REAL_API=true)', () => {
    test('when force overwrite with real API, then returns 201', async () => {
      if (!ttsEnabled || !ttsRealApi) return;
      if (!realElevenLabsVoiceId) return;
      if (!global.helpers.isFFmpegAvailable()) return;

      // Arrange
      const voiceId = await createVoice('TTS Force Voice', realElevenLabsVoiceId);
      expect(voiceId).not.toBeNull();

      const storyId = await createStory(
        'TTS Force Overwrite Story',
        'Dit is een test verhaal voor tekst naar spraak.',
        voiceId
      );
      expect(storyId).not.toBeNull();

      const uploaded = await uploadTestAudio(storyId);
      expect(uploaded).toBe(true);

      // Act
      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts?force=true`);

      // Assert
      expect(response.status).toBe(201);
    });

    test('when generating TTS for story without audio, then returns 201', async () => {
      if (!ttsEnabled || !ttsRealApi) return;
      if (!realElevenLabsVoiceId) return;

      // Arrange
      const voiceId = await createVoice('TTS Happy Path Voice', realElevenLabsVoiceId);
      expect(voiceId).not.toBeNull();

      const storyId = await createStory(
        'TTS Happy Path Story',
        'Dit is een test verhaal voor tekst naar spraak.',
        voiceId
      );
      expect(storyId).not.toBeNull();

      // Verify story has no audio yet
      const beforeResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(beforeResponse.status).toBe(200);

      // Act
      const response = await global.api.apiCall('POST', `/stories/${storyId}/tts`);

      // Assert
      expect(response.status).toBe(201);

      // Verify story now has audio
      const afterResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(afterResponse.status).toBe(200);
      expect(afterResponse.data.audio_file).toBeTruthy();
      expect(afterResponse.data.audio_url).toBeTruthy();
    });
  });
});
