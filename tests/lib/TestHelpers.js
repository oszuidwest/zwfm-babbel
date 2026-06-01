// Centralized test helper functions for Babbel API tests.
// Eliminates code duplication across test files by providing unified helper methods.

const { execFileSync } = require('child_process');
const fsSync = require('fs');

const { commandErrorMessage } = require('./MySQLHelper');
const { parseFiniteNumber, parseSafeInteger } = require('./numeric');

class TestHelpers {
  /** Automation key matching docker-compose BABBEL_AUTOMATION_KEY */
  static AUTOMATION_KEY = 'test-automation-key-for-integration-tests';

  constructor(apiHelper) {
    this.api = apiHelper;
    this._ffmpegAvailable = null;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // General Utilities
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Delays execution for the specified number of milliseconds.
   * @param {number} ms - Milliseconds to wait.
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Polls a story endpoint until audio_url is available.
   * Replaces magic sleep() calls after audio upload.
   * @param {number} storyId - Story ID to check.
   * @param {number} timeoutMs - Max wait time (default: 10000).
   * @param {number} intervalMs - Poll interval (default: 500).
   * @returns {Promise<boolean>} True if audio became available within timeout.
   */
  async waitForStoryAudio(storyId, timeoutMs = 10000, intervalMs = 500) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const response = await this.api.apiCall('GET', `/stories/${storyId}`);
      if (response.status === 200 && response.data.audio_url) {
        return true;
      }
      await this.sleep(intervalMs);
    }
    return false;
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
        execFileSync('ffmpeg', ['-version'], { stdio: 'ignore' });
        this._ffmpegAvailable = true;
      } catch (error) {
        this._ffmpegAvailable = false;
        console.warn(`ffmpeg is not available: ${commandErrorMessage(error)}`);
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
    const numericDuration = parseFiniteNumber(duration, 'audio duration');
    const numericFrequency = parseFiniteNumber(frequency, 'audio frequency');

    if (!this.isFFmpegAvailable()) {
      return false;
    }

    try {
      execFileSync(
        'ffmpeg',
        [
          '-f', 'lavfi',
          '-i', `sine=frequency=${numericFrequency}:duration=${numericDuration}`,
          '-ar', '44100',
          '-ac', '2',
          '-f', 'wav',
          outputPath,
          '-y'
        ],
        { stdio: 'ignore' }
      );
      if (!fsSync.existsSync(outputPath)) {
        throw new Error('ffmpeg completed but output file was not created');
      }
      return true;
    } catch (error) {
      console.warn(`Failed to create test audio file ${outputPath}: ${commandErrorMessage(error)}`);
      return false;
    }
  }

  /**
   * Cleans up a temporary file if it exists.
   * @param {string} filePath - Path to the file to remove.
   */
  cleanupTempFile(filePath) {
    try {
      fsSync.unlinkSync(filePath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.warn(`Failed to clean up temporary file ${filePath}: ${error.message}`);
      }
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
   * @returns {Promise<{id: number, name: string}|null>} Station data or null if failed.
   */
  async createStation(resourceManager, name, maxStories = 4, pauseSeconds = 2.0) {
    const uniqueName = this.uniqueName(name);

    const response = await this.api.apiCall('POST', '/stations', {
      name: uniqueName,
      max_stories_per_block: maxStories,
      pause_seconds: pauseSeconds
    });

    if (response.status === 201 && response.data?.id) {
      resourceManager.track('stations', response.data.id);
      return { id: response.data.id, name: uniqueName };
    }

    return null;
  }

  /**
   * Creates a test voice.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {string} name - Base name for the voice.
   * @returns {Promise<{id: number, name: string}|null>} Voice data or null if failed.
   */
  async createVoice(resourceManager, name) {
    const uniqueName = this.uniqueName(name);

    const response = await this.api.apiCall('POST', '/voices', {
      name: uniqueName
    });

    if (response.status === 201 && response.data?.id) {
      resourceManager.track('voices', response.data.id);
      return { id: response.data.id, name: uniqueName };
    }

    return null;
  }

  /**
   * Creates a test story without audio.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {Object} data - Story data (title, text, voice_id, etc.).
   * @param {Array<number>} targetStations - Array of station IDs to target.
   * @returns {Promise<{id: number}|null>} Story data or null if failed.
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
      voice_id: data.voice_id !== undefined && data.voice_id !== null
        ? parseSafeInteger(data.voice_id, 'voice_id')
        : null,
      status: data.status || 'active',
      start_date: data.start_date || `${year}-01-01`,
      end_date: data.end_date || `${year + 1}-12-31`,
      weekdays: data.weekdays !== undefined ? data.weekdays : 127,
      is_breaking: data.is_breaking !== undefined ? data.is_breaking : false,
      target_stations: targetStations.map(id => parseSafeInteger(id, 'target station ID')),
      metadata: data.metadata || null
    };

    const response = await this.api.apiCall('POST', '/stories', storyData);

    if (response.status === 201 && response.data?.id) {
      resourceManager.track('stories', response.data.id);
      return { id: response.data.id };
    }

    return null;
  }

  /**
   * Creates a test story with audio file.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {Object} data - Story data (title, text, voice_id, etc.).
   * @param {Array<number>} targetStations - Array of station IDs to target.
   * @returns {Promise<{id: number}|null>} Story data or null if failed.
   */
  async createStoryWithAudio(resourceManager, data, targetStations) {
    if (!this.isFFmpegAvailable()) {
      return null;
    }

    const audioFile = `/tmp/test_story_${Date.now()}.wav`;

    if (!this.createTestAudioFile(audioFile, 3, 220)) {
      return null;
    }

    try {
      const story = await this.createStory(resourceManager, data, targetStations);

      if (!story) {
        return null;
      }

      const uploadResponse = await this.api.uploadFile(
        `/stories/${story.id}/audio`,
        {},
        audioFile,
        'audio'
      );

      return uploadResponse.status === 201 ? story : null;
    } finally {
      this.cleanupTempFile(audioFile);
    }
  }

  /**
   * Creates a test story with audio and waits until the API exposes it.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {Object} data - Story data (title, text, voice_id, etc.).
   * @param {Array<number>} targetStations - Array of station IDs to target.
   * @returns {Promise<{id: number}>} Story data.
   */
  async createStoryWithReadyAudio(resourceManager, data, targetStations) {
    const story = await this.createStoryWithAudio(resourceManager, data, targetStations);
    if (!story) {
      throw new Error(`Failed to create story-with-audio fixture: ${data.title || 'untitled story'}`);
    }

    const audioReady = await this.waitForStoryAudio(story.id);
    if (!audioReady) {
      throw new Error(`Timed out waiting for story audio fixture: ${story.id}`);
    }

    return story;
  }

  /**
   * Creates multiple ready audio stories for one station/voice pair.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {string|number} stationId - Station ID.
   * @param {string|number} voiceId - Voice ID.
   * @param {Array<Object>} stories - Story overrides.
   * @returns {Promise<Array<{id: number}>>} Created stories in input order.
   */
  async createStationStoriesWithReadyAudio(resourceManager, stationId, voiceId, stories) {
    const safeStationId = parseSafeInteger(stationId, 'station ID');
    const safeVoiceId = parseSafeInteger(voiceId, 'voice ID');
    const created = [];

    for (const story of stories) {
      created.push(await this.createStoryWithReadyAudio(resourceManager, {
        voice_id: safeVoiceId,
        weekdays: 127,
        status: 'active',
        ...story
      }, [safeStationId]));
    }

    return created;
  }

  /**
   * Creates a station-voice relationship without jingle.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {string|number} stationId - Station ID.
   * @param {string|number} voiceId - Voice ID.
   * @param {number} mixPoint - Mix point in seconds (default: 3.0).
   * @returns {Promise<{id: number}|null>} Station-voice data or null if failed.
   */
  async createStationVoice(resourceManager, stationId, voiceId, mixPoint = 3.0) {
    const response = await this.api.apiCall('POST', '/station-voices', {
      station_id: parseSafeInteger(stationId, 'station ID'),
      voice_id: parseSafeInteger(voiceId, 'voice ID'),
      mix_point: parseFiniteNumber(mixPoint, 'mix point')
    });

    if (response.status === 201 && response.data?.id) {
      resourceManager.track('stationVoices', response.data.id);
      return { id: response.data.id };
    }

    return null;
  }

  /**
   * Creates a station-voice relationship with jingle audio.
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {string|number} stationId - Station ID.
   * @param {string|number} voiceId - Voice ID.
   * @param {number} mixPoint - Mix point in seconds (default: 3.0).
   * @returns {Promise<{id: number}|null>} Station-voice data or null if failed.
   */
  async createStationVoiceWithJingle(resourceManager, stationId, voiceId, mixPoint = 3.0) {
    const safeStationId = parseSafeInteger(stationId, 'station ID');
    const safeVoiceId = parseSafeInteger(voiceId, 'voice ID');

    if (!this.isFFmpegAvailable()) {
      return null;
    }

    const jingleFile = `/tmp/test_jingle_${safeStationId}_${safeVoiceId}_${Date.now()}.wav`;

    if (!this.createTestAudioFile(jingleFile, 5, 440)) {
      return null;
    }

    try {
      const stationVoice = await this.createStationVoice(resourceManager, safeStationId, safeVoiceId, mixPoint);

      if (!stationVoice) {
        return null;
      }

      // Jingle upload is best-effort: station-voice remains valid even if it fails.
      await this.api.uploadFile(
        `/station-voices/${stationVoice.id}/audio`,
        {},
        jingleFile,
        'jingle'
      );

      return stationVoice;
    } finally {
      this.cleanupTempFile(jingleFile);
    }
  }

  /**
   * Creates the common station -> voice -> jingle -> story-with-audio fixture
   * needed by bulletin and automation integration tests.
   *
   * @param {Object} resourceManager - ResourceManager instance for tracking.
   * @param {Object} options - Fixture options.
   * @returns {Promise<{station: Object, voice: Object, stationVoice: Object, story: Object}>}
   */
  async createBroadcastFixture(resourceManager, options = {}) {
    const {
      stationName = 'BroadcastStation',
      voiceName = 'BroadcastVoice',
      storyTitle = 'BroadcastStory',
      storyText = 'Broadcast fixture story',
      maxStories = 4,
      pauseSeconds = 2.0,
      mixPoint = 3.0,
      storyOverrides = {}
    } = options;

    const station = await this.createStation(resourceManager, stationName, maxStories, pauseSeconds);
    if (!station) {
      throw new Error(`Failed to create station fixture: ${stationName}`);
    }

    const voice = await this.createVoice(resourceManager, voiceName);
    if (!voice) {
      throw new Error(`Failed to create voice fixture: ${voiceName}`);
    }

    const stationVoice = await this.createStationVoiceWithJingle(resourceManager, station.id, voice.id, mixPoint);
    if (!stationVoice) {
      throw new Error(`Failed to create station-voice fixture for station ${station.id} and voice ${voice.id}`);
    }

    const storyData = {
      title: this.uniqueName(storyTitle),
      text: storyText,
      voice_id: voice.id,
      weekdays: 127,
      status: 'active',
      ...storyOverrides
    };

    const story = await this.createStoryWithReadyAudio(resourceManager, storyData, [station.id]);

    return { station, voice, stationVoice, story };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Public Endpoint Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Makes a public bulletin request (bypasses authentication).
   * @param {string|number} stationId - Station ID.
   * @param {Object} queryParams - Query parameters (key, max_age, etc.).
   * @returns {Promise<{status: number, data: *, headers: Object, contentType: string}>}
   */
  async publicBulletinRequest(stationId, queryParams = {}) {
    const safeStationId = parseSafeInteger(stationId, 'station ID');
    const params = new URLSearchParams(queryParams);
    const url = `${this.api.apiBase}/public/stations/${safeStationId}/bulletin.wav?${params.toString()}`;

    const response = await this.api.http({
      method: 'get',
      url: url,
      responseType: 'arraybuffer',
      validateStatus: () => true
    });

    return {
      status: response.status,
      data: response.data,
      headers: response.headers,
      contentType: response.headers['content-type']
    };
  }
}

module.exports = TestHelpers;
