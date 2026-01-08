// Centralized test helper functions for Babbel API tests.
// Eliminates code duplication across test files by providing unified helper methods.

const { execSync } = require('child_process');
const fsSync = require('fs');

class TestHelpers {
    constructor(apiHelper) {
        this.api = apiHelper;
        this._ffmpegAvailable = null;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FFmpeg Utilities
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Checks if ffmpeg is available on the system.
     * Result is cached for performance.
     * @returns {boolean} True if ffmpeg is available.
     */
    isFFmpegAvailable() {
        if (this._ffmpegAvailable === null) {
            try {
                execSync('ffmpeg -version', { stdio: 'ignore' });
                this._ffmpegAvailable = true;
            } catch {
                this._ffmpegAvailable = false;
            }
        }
        return this._ffmpegAvailable;
    }

    /**
     * Creates a test audio file using ffmpeg.
     * @param {string} outputPath - Path to write the audio file.
     * @param {number} duration - Duration in seconds (default: 3).
     * @param {number} frequency - Sine wave frequency in Hz (default: 440).
     * @returns {boolean} True if file was created successfully.
     */
    createTestAudioFile(outputPath, duration = 3, frequency = 440) {
        if (!this.isFFmpegAvailable()) {
            return false;
        }

        try {
            execSync(
                `ffmpeg -f lavfi -i "sine=frequency=${frequency}:duration=${duration}" -ar 44100 -ac 2 -f wav "${outputPath}" -y 2>/dev/null`,
                { stdio: 'ignore' }
            );
            return fsSync.existsSync(outputPath);
        } catch {
            return false;
        }
    }

    /**
     * Cleans up a temporary file if it exists.
     * @param {string} filePath - Path to the file to remove.
     */
    cleanupTempFile(filePath) {
        try {
            if (fsSync.existsSync(filePath)) {
                fsSync.unlinkSync(filePath);
            }
        } catch {
            // Ignore cleanup errors
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Resource Creation Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Generates a unique name for test resources.
     * @param {string} baseName - Base name for the resource.
     * @returns {string} Unique name with timestamp and process ID.
     */
    uniqueName(baseName) {
        return `${baseName}_${Date.now()}_${process.pid}`;
    }

    /**
     * Creates a test station.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {string} name - Base name for the station.
     * @param {number} maxStories - Max stories per block (default: 4).
     * @param {number} pauseSeconds - Pause between stories (default: 2.0).
     * @returns {Promise<{id: string, name: string}|null>} Station data or null if failed.
     */
    async createStation(resourceManager, name, maxStories = 4, pauseSeconds = 2.0) {
        const uniqueName = this.uniqueName(name);

        const response = await this.api.apiCall('POST', '/stations', {
            name: uniqueName,
            max_stories_per_block: maxStories,
            pause_seconds: pauseSeconds
        });

        if (response.status === 201) {
            const id = this.api.parseJsonField(response.data, 'id');
            if (id) {
                resourceManager.track('stations', id);
                return { id, name: uniqueName };
            }
        }

        return null;
    }

    /**
     * Creates a test voice.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {string} name - Base name for the voice.
     * @returns {Promise<{id: string, name: string}|null>} Voice data or null if failed.
     */
    async createVoice(resourceManager, name) {
        const uniqueName = this.uniqueName(name);

        const response = await this.api.apiCall('POST', '/voices', {
            name: uniqueName
        });

        if (response.status === 201) {
            const id = this.api.parseJsonField(response.data, 'id');
            if (id) {
                resourceManager.track('voices', id);
                return { id, name: uniqueName };
            }
        }

        return null;
    }

    /**
     * Creates a test story without audio.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {Object} data - Story data (title, text, voice_id, etc.).
     * @param {Array<number>} targetStations - Array of station IDs to target.
     * @returns {Promise<{id: string}|null>} Story data or null if failed.
     */
    async createStory(resourceManager, data, targetStations) {
        if (!targetStations || targetStations.length === 0) {
            return null;
        }

        const today = new Date();
        const year = today.getFullYear();

        const storyData = {
            title: data.title || this.uniqueName('TestStory'),
            text: data.text || 'Test story content',
            voice_id: data.voice_id ? parseInt(data.voice_id, 10) : null,
            status: data.status || 'active',
            start_date: data.start_date || `${year}-01-01`,
            end_date: data.end_date || `${year + 1}-12-31`,
            weekdays: data.weekdays !== undefined ? data.weekdays : 127,
            target_stations: targetStations.map(id => parseInt(id, 10)),
            metadata: data.metadata || null
        };

        const response = await this.api.apiCall('POST', '/stories', storyData);

        if (response.status === 201) {
            const id = this.api.parseJsonField(response.data, 'id');
            if (id) {
                resourceManager.track('stories', id);
                return { id };
            }
        }

        return null;
    }

    /**
     * Creates a test story with audio file.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {Object} data - Story data (title, text, voice_id, etc.).
     * @param {Array<number>} targetStations - Array of station IDs to target.
     * @returns {Promise<{id: string}|null>} Story data or null if failed.
     */
    async createStoryWithAudio(resourceManager, data, targetStations) {
        if (!this.isFFmpegAvailable()) {
            return null;
        }

        const audioFile = `/tmp/test_story_${Date.now()}.wav`;

        if (!this.createTestAudioFile(audioFile, 3, 220)) {
            return null;
        }

        // Create story first
        const story = await this.createStory(resourceManager, data, targetStations);

        if (!story) {
            this.cleanupTempFile(audioFile);
            return null;
        }

        // Upload audio
        const uploadResponse = await this.api.uploadFile(
            `/stories/${story.id}/audio`,
            {},
            audioFile,
            'audio'
        );

        this.cleanupTempFile(audioFile);

        if (uploadResponse.status !== 201) {
            return null;
        }

        return story;
    }

    /**
     * Creates a station-voice relationship without jingle.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {string|number} stationId - Station ID.
     * @param {string|number} voiceId - Voice ID.
     * @param {number} mixPoint - Mix point in seconds (default: 3.0).
     * @returns {Promise<{id: string}|null>} Station-voice data or null if failed.
     */
    async createStationVoice(resourceManager, stationId, voiceId, mixPoint = 3.0) {
        const response = await this.api.apiCall('POST', '/station-voices', {
            station_id: parseInt(stationId, 10),
            voice_id: parseInt(voiceId, 10),
            mix_point: parseFloat(mixPoint)
        });

        if (response.status === 201) {
            const id = this.api.parseJsonField(response.data, 'id');
            if (id) {
                resourceManager.track('stationVoices', id);
                return { id };
            }
        }

        return null;
    }

    /**
     * Creates a station-voice relationship with jingle audio.
     * @param {Object} resourceManager - ResourceManager instance for tracking.
     * @param {string|number} stationId - Station ID.
     * @param {string|number} voiceId - Voice ID.
     * @param {number} mixPoint - Mix point in seconds (default: 3.0).
     * @returns {Promise<{id: string}|null>} Station-voice data or null if failed.
     */
    async createStationVoiceWithJingle(resourceManager, stationId, voiceId, mixPoint = 3.0) {
        if (!this.isFFmpegAvailable()) {
            return null;
        }

        const jingleFile = `/tmp/test_jingle_${stationId}_${voiceId}_${Date.now()}.wav`;

        if (!this.createTestAudioFile(jingleFile, 5, 440)) {
            return null;
        }

        // Create station-voice first
        const stationVoice = await this.createStationVoice(resourceManager, stationId, voiceId, mixPoint);

        if (!stationVoice) {
            this.cleanupTempFile(jingleFile);
            return null;
        }

        // Upload jingle
        const uploadResponse = await this.api.uploadFile(
            `/station-voices/${stationVoice.id}/audio`,
            {},
            jingleFile,
            'jingle'
        );

        this.cleanupTempFile(jingleFile);

        // Jingle upload is optional - station-voice is still valid without it
        return stationVoice;
    }
}

module.exports = TestHelpers;
