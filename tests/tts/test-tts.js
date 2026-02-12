// Babbel TTS (text-to-speech) integration tests.
// Tests the POST /api/v1/stories/{id}/tts endpoint validation chain.
// Adapts to whether TTS is enabled or disabled on the server.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

// ID that should never exist in any realistic database. Used for "not found" probes.
// MySQL auto-increment will not reach this value in test environments.
const NONEXISTENT_STORY_ID = 2147483647;

class TTSTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);

        // Track created resources for cleanup
        this.createdStoryIds = [];
        this.createdVoiceIds = [];

        // TTS mode flags (set during setup)
        this.ttsEnabled = false;
        this.ttsRealApi = false;
        this.realElevenLabsVoiceId = null;
    }

    /**
     * Helper to create a voice and track it for cleanup.
     */
    async createVoice(baseName, elevenLabsVoiceId = null) {
        const uniqueName = `${baseName}_${Date.now()}_${process.pid}`;
        const payload = { name: uniqueName };
        if (elevenLabsVoiceId) {
            payload.elevenlabs_voice_id = elevenLabsVoiceId;
        }

        const response = await this.apiCall('POST', '/voices', payload);
        if (response.status === 201) {
            const voiceId = this.parseJsonField(response.data, 'id');
            if (voiceId) {
                this.createdVoiceIds.push(voiceId);
                return voiceId;
            }
        }

        return null;
    }

    /**
     * Helper to create a story and track it for cleanup.
     */
    async createStory(title, text, voiceId = null) {
        const storyData = {
            title,
            text,
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2030-12-31',
            weekdays: 127,
        };

        const response = await this.apiCall('POST', '/stories', storyData);
        if (response.status === 201) {
            const storyId = this.parseJsonField(response.data, 'id');
            if (storyId) {
                this.createdStoryIds.push(storyId);
                return storyId;
            }
        }

        return null;
    }

    /**
     * Detect whether TTS is enabled on the server.
     * A 501 response means TTS is disabled (no API key configured).
     * A 404 response means TTS is enabled (story not found, but TTS handler ran).
     * Any other status is unexpected and gets a warning.
     */
    async detectTTSMode() {
        const probe = await this.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);
        this.ttsEnabled = (probe.status !== 501);

        if (this.ttsEnabled && probe.status !== 404) {
            this.printWarning(`TTS probe returned unexpected status ${probe.status} (expected 404 or 501) — story ID ${NONEXISTENT_STORY_ID} may exist`);
        }

        this.ttsRealApi = process.env.BABBEL_TEST_TTS_REAL_API === 'true';
        this.realElevenLabsVoiceId = process.env.BABBEL_TEST_ELEVENLABS_VOICE_ID || null;

        if (this.ttsEnabled) {
            this.printInfo('TTS is enabled on this server');
            if (this.ttsRealApi) {
                this.printInfo('Real ElevenLabs API tests are enabled');
                if (this.realElevenLabsVoiceId) {
                    this.printInfo(`Using ElevenLabs voice ID: ${this.realElevenLabsVoiceId}`);
                } else {
                    this.printWarning('BABBEL_TEST_ELEVENLABS_VOICE_ID not set — real API tests may fail');
                }
            } else {
                this.printInfo('Real ElevenLabs API tests are disabled (set BABBEL_TEST_TTS_REAL_API=true to enable)');
            }
        } else {
            this.printInfo('TTS is disabled on this server (no API key configured)');
        }
    }

    // ── Test methods ────────────────────────────────────────────

    /**
     * Test 1: TTS disabled returns 501 with correct problem type.
     * Only runs when TTS is NOT enabled.
     */
    async testTtsDisabled() {
        this.printSection('Testing TTS Disabled (501)');

        if (this.ttsEnabled) {
            this.printInfo('Skipping: TTS is enabled on this server');
            return true;
        }

        const response = await this.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

        if (!this.assertions.assertStatusCode(response.status, 501, 'TTS disabled status')) {
            return false;
        }

        // Verify RFC 9457 problem details type
        const type = response.data && response.data.type;
        if (!type || !type.includes('tts.not_configured')) {
            this.printError(`Expected type containing 'tts.not_configured', got: ${type}`);
            return false;
        }
        this.printSuccess('Problem type contains tts.not_configured');

        return true;
    }

    /**
     * Test 2: TTS on non-existent story returns 404.
     * Only runs when TTS IS enabled.
     */
    async testTtsStoryNotFound() {
        this.printSection('Testing TTS Story Not Found (404)');

        if (!this.ttsEnabled) {
            this.printInfo('Skipping: TTS is disabled on this server');
            return true;
        }

        const response = await this.apiCall('POST', `/stories/${NONEXISTENT_STORY_ID}/tts`);

        if (!this.assertions.assertStatusCode(response.status, 404, 'Non-existent story')) {
            return false;
        }

        const type = response.data && response.data.type;
        if (!type || !type.includes('story.not_found')) {
            this.printError(`Expected type containing 'story.not_found', got: ${type}`);
            return false;
        }
        this.printSuccess('Problem type contains story.not_found');

        return true;
    }

    /**
     * Test 3: TTS on story without voice_id returns 400.
     * Only runs when TTS IS enabled.
     */
    async testTtsStoryNoVoice() {
        this.printSection('Testing TTS Story Without Voice');

        if (!this.ttsEnabled) {
            this.printInfo('Skipping: TTS is disabled on this server');
            return true;
        }

        // Create story without a voice
        const storyId = await this.createStory('TTS No Voice Story', 'Some text content for TTS');
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        const response = await this.apiCall('POST', `/stories/${storyId}/tts`);

        if (!this.assertions.assertStatusCode(response.status, 400, 'Story without voice')) {
            this.printInfo(`Response body: ${JSON.stringify(response.data)}`);
            return false;
        }

        const type = response.data && response.data.type;
        if (!type || !type.includes('story.validation_failed')) {
            this.printError(`Expected type containing 'story.validation_failed', got: ${type}`);
            return false;
        }
        this.printSuccess('Correctly rejected story without voice_id');

        return true;
    }

    /**
     * Test 4: TTS on story whose voice has no elevenlabs_voice_id returns 400.
     * Only runs when TTS IS enabled.
     */
    async testTtsVoiceNoElevenlabsId() {
        this.printSection('Testing TTS Voice Without ElevenLabs ID');

        if (!this.ttsEnabled) {
            this.printInfo('Skipping: TTS is disabled on this server');
            return true;
        }

        // Create voice WITHOUT elevenlabs_voice_id
        const voiceId = await this.createVoice('TTS No EL Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Create story with that voice
        const storyId = await this.createStory('TTS No EL ID Story', 'Some text content for TTS', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        const response = await this.apiCall('POST', `/stories/${storyId}/tts`);

        if (!this.assertions.assertStatusCode(response.status, 400, 'Voice without ElevenLabs ID')) {
            this.printInfo(`Response body: ${JSON.stringify(response.data)}`);
            return false;
        }

        const type = response.data && response.data.type;
        if (!type || !type.includes('voice.validation_failed')) {
            this.printError(`Expected type containing 'voice.validation_failed', got: ${type}`);
            return false;
        }
        this.printSuccess('Correctly rejected voice without elevenlabs_voice_id');

        return true;
    }

    /**
     * Test 5: TTS on story that already has audio (without force) returns 400.
     * Only runs when TTS IS enabled and ffmpeg is available.
     */
    async testTtsStoryAlreadyHasAudio() {
        this.printSection('Testing TTS Story Already Has Audio');

        if (!this.ttsEnabled) {
            this.printInfo('Skipping: TTS is disabled on this server');
            return true;
        }

        // Create voice with a dummy elevenlabs_voice_id (won't actually call ElevenLabs)
        const voiceId = await this.createVoice('TTS Audio Exists Voice', 'dummy-el-voice-id');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Create story with that voice
        const storyId = await this.createStory('TTS Audio Exists Story', 'Some text content for TTS', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        // Upload audio to the story so it already has an audio file
        const testAudioPath = '/tmp/tts_test_audio.wav';
        const fs = require('fs');
        const { execSync } = require('child_process');

        try {
            execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=mono -t 1 -f wav "${testAudioPath}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fs.existsSync(testAudioPath)) {
                this.printInfo('Skipping: Could not create test audio file (ffmpeg unavailable)');
                return true;
            }
        } catch (error) {
            this.printInfo('Skipping: ffmpeg not available for creating test audio');
            return true;
        }

        try {
            const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, testAudioPath, 'audio');
            if (uploadResponse.status !== 201) {
                this.printError(`Audio upload failed (HTTP ${uploadResponse.status}) — this is a precondition failure`);
                this.printError(`Response: ${JSON.stringify(uploadResponse.data)}`);
                return false;
            }
            this.printSuccess('Audio uploaded to story');

            // Now try TTS without force — should be rejected
            const response = await this.apiCall('POST', `/stories/${storyId}/tts`);

            if (!this.assertions.assertStatusCode(response.status, 400, 'Story already has audio')) {
                this.printInfo(`Response body: ${JSON.stringify(response.data)}`);
                return false;
            }

            const type = response.data && response.data.type;
            if (!type || !type.includes('story.validation_failed')) {
                this.printError(`Expected type containing 'story.validation_failed', got: ${type}`);
                return false;
            }

            // Verify the detail mentions force
            const detail = response.data && response.data.detail;
            if (detail && detail.includes('force')) {
                this.printSuccess('Error message mentions ?force=true');
            } else {
                this.printWarning('Error message does not mention force parameter');
            }

            this.printSuccess('Correctly rejected TTS when story already has audio');
            return true;
        } finally {
            try { fs.unlinkSync(testAudioPath); } catch (e) { /* ignore */ }
        }
    }

    /**
     * Test 6: TTS with ?force=true overwrites existing audio.
     * Only runs with real ElevenLabs API access.
     */
    async testTtsForceOverwrite() {
        this.printSection('Testing TTS Force Overwrite');

        if (!this.ttsEnabled || !this.ttsRealApi) {
            this.printInfo('Skipping: Requires TTS enabled + BABBEL_TEST_TTS_REAL_API=true');
            return true;
        }

        if (!this.realElevenLabsVoiceId) {
            this.printInfo('Skipping: BABBEL_TEST_ELEVENLABS_VOICE_ID not set');
            return true;
        }

        // Create voice with real ElevenLabs voice ID
        const voiceId = await this.createVoice('TTS Force Voice', this.realElevenLabsVoiceId);
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Create story
        const storyId = await this.createStory('TTS Force Overwrite Story', 'Dit is een test verhaal voor tekst naar spraak.', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        // Upload dummy audio first
        const testAudioPath = '/tmp/tts_force_test_audio.wav';
        const fs = require('fs');
        const { execSync } = require('child_process');

        try {
            execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=mono -t 1 -f wav "${testAudioPath}" -y 2>/dev/null`, { stdio: 'ignore' });
        } catch (error) {
            this.printInfo('Skipping: ffmpeg not available');
            return true;
        }

        try {
            const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, testAudioPath, 'audio');
            if (uploadResponse.status !== 201) {
                this.printError(`Audio upload failed (HTTP ${uploadResponse.status}) — this is a precondition failure`);
                this.printError(`Response: ${JSON.stringify(uploadResponse.data)}`);
                return false;
            }

            // Now TTS with force=true — should succeed
            const response = await this.apiCall('POST', `/stories/${storyId}/tts?force=true`);

            if (!this.assertions.assertStatusCode(response.status, 201, 'TTS force overwrite')) {
                this.printInfo(`Response body: ${JSON.stringify(response.data)}`);
                return false;
            }

            this.printSuccess('TTS force overwrite succeeded');
            return true;
        } finally {
            try { fs.unlinkSync(testAudioPath); } catch (e) { /* ignore */ }
        }
    }

    /**
     * Test 7: Full TTS happy path — generate audio for a story.
     * Only runs with real ElevenLabs API access.
     */
    async testTtsHappyPath() {
        this.printSection('Testing TTS Happy Path');

        if (!this.ttsEnabled || !this.ttsRealApi) {
            this.printInfo('Skipping: Requires TTS enabled + BABBEL_TEST_TTS_REAL_API=true');
            return true;
        }

        if (!this.realElevenLabsVoiceId) {
            this.printInfo('Skipping: BABBEL_TEST_ELEVENLABS_VOICE_ID not set');
            return true;
        }

        // Create voice with real ElevenLabs voice ID
        const voiceId = await this.createVoice('TTS Happy Path Voice', this.realElevenLabsVoiceId);
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Create story without audio
        const storyId = await this.createStory('TTS Happy Path Story', 'Dit is een test verhaal voor tekst naar spraak.', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        // Verify story has no audio yet
        const beforeResponse = await this.apiCall('GET', `/stories/${storyId}`);
        if (beforeResponse.status === 200 && beforeResponse.data.audio_file === '') {
            this.printSuccess('Story has no audio before TTS');
        }

        // Call TTS endpoint
        this.printInfo('Calling TTS endpoint (this may take a few seconds)...');
        const response = await this.apiCall('POST', `/stories/${storyId}/tts`);

        if (!this.assertions.assertStatusCode(response.status, 201, 'TTS generation')) {
            this.printInfo(`Response body: ${JSON.stringify(response.data)}`);
            return false;
        }

        this.printSuccess('TTS audio generated successfully');

        // Verify story now has audio
        const afterResponse = await this.apiCall('GET', `/stories/${storyId}`);
        if (afterResponse.status === 200) {
            if (afterResponse.data.audio_file && afterResponse.data.audio_file !== '') {
                this.printSuccess(`Story now has audio file: ${afterResponse.data.audio_file}`);
            } else {
                this.printError('Story still has no audio file after TTS generation');
                return false;
            }

            if (afterResponse.data.audio_url && afterResponse.data.audio_url !== '') {
                this.printSuccess('Story has audio URL');
            } else {
                this.printError('Story has no audio URL after TTS generation');
                return false;
            }
        } else {
            this.printError(`Failed to fetch story after TTS (HTTP ${afterResponse.status})`);
            return false;
        }

        return true;
    }

    // ── Lifecycle ───────────────────────────────────────────────

    async setup() {
        this.printInfo('Setting up TTS tests...');
        await this.restoreAdminSession();
        await this.detectTTSMode();
        return true;
    }

    async cleanup() {
        this.printInfo('Cleaning up TTS tests...');

        // Delete stories first (they reference voices)
        for (const storyId of this.createdStoryIds) {
            try {
                const res = await this.apiCall('DELETE', `/stories/${storyId}`);
                if (res.status === 204 || res.status === 404) {
                    this.printInfo(`Cleaned up story: ${storyId}`);
                } else {
                    this.printWarning(`Cleanup story ${storyId} returned HTTP ${res.status}`);
                }
            } catch (error) {
                this.printWarning(`Cleanup story ${storyId} failed: ${error.message}`);
            }
        }

        // Then delete voices
        for (const voiceId of this.createdVoiceIds) {
            try {
                const res = await this.apiCall('DELETE', `/voices/${voiceId}`);
                if (res.status === 204 || res.status === 404) {
                    this.printInfo(`Cleaned up voice: ${voiceId}`);
                } else {
                    this.printWarning(`Cleanup voice ${voiceId} returned HTTP ${res.status}`);
                }
            } catch (error) {
                this.printWarning(`Cleanup voice ${voiceId} failed: ${error.message}`);
            }
        }

        return true;
    }

    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            return await this.apiLogin();
        }
        return true;
    }

    async run() {
        this.printHeader('TTS Tests');

        await this.setup();

        const tests = [
            'testTtsDisabled',
            'testTtsStoryNotFound',
            'testTtsStoryNoVoice',
            'testTtsVoiceNoElevenlabsId',
            'testTtsStoryAlreadyHasAudio',
            'testTtsForceOverwrite',
            'testTtsHappyPath',
        ];

        let failed = 0;

        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error('');
        }

        await this.cleanup();

        this.printSummary();

        if (failed === 0) {
            this.printSuccess('All TTS tests passed!');
            return true;
        } else {
            this.printError(`${failed} TTS tests failed`);
            return false;
        }
    }
}

module.exports = TTSTests;
// Run tests if executed directly
if (require.main === module) {
    const TestClass = module.exports;
    const test = new TestClass();
    test.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}
