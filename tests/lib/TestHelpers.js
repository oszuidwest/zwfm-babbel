// Shared integration-test helpers.

const { execFileSync } = require('child_process');
const fsSync = require('fs');

const { commandErrorMessage } = require('./MySQLHelper');
const { parseFiniteNumber, parseSafeInteger } = require('./numeric');

class TestHelpers {
  // Must match the integration environment.
  static AUTOMATION_KEY = process.env.BABBEL_AUTOMATION_KEY || 'test-automation-key-for-integration-tests';

  constructor(apiHelper) {
    this.api = apiHelper;
    this._ffmpegAvailable = null;
  }

  /** @param {number} ms */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Polls instead of assuming audio processing latency.
   * @param {number} storyId
   * @param {number} [timeoutMs]
   * @param {number} [intervalMs]
   * @returns {Promise<boolean>}
   */
  async waitForStoryAudio(storyId, timeoutMs = 10000, intervalMs = 500) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const response = await this.api.apiCall('GET', `/stories/${storyId}`);
      this.fixtureResponse(response, 'GET', `/stories/${storyId}`, 200, false);
      if (response.data.audio_url) {
        return true;
      }
      await this.sleep(intervalMs);
    }
    return false;
  }

  /**
   * Polls to a terminal state; throws on HTTP errors or timeout.
   * @param {number} jobId
   * @param {number} [timeoutMs]
   * @param {number} [intervalMs]
   * @returns {Promise<Object>}
   */
  async waitForBulletinJob(jobId, timeoutMs = 45000, intervalMs = 250) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const response = await this.api.apiCall('GET', `/bulletin-jobs/${jobId}`);
      this.fixtureResponse(response, 'GET', `/bulletin-jobs/${jobId}`, 200, false);
      if (['succeeded', 'failed'].includes(response.data.status)) {
        return response;
      }
      await this.sleep(intervalMs);
    }
    throw new Error(`Bulletin job ${jobId} did not finish within ${timeoutMs / 1000} seconds`);
  }

  /**
   * Enqueues and resolves a bulletin; non-202 responses pass through.
   * @param {number} stationId
   * @returns {Promise<Object>}
   */
  async generateBulletin(stationId) {
    const accepted = await this.api.apiCall('POST', `/stations/${stationId}/bulletins`);
    if (accepted.status !== 202) return accepted;
    const job = await this.waitForBulletinJob(accepted.data.id);
    if (job.data.status === 'failed') {
      throw new Error(`Bulletin job ${accepted.data.id} failed: ${job.data.error_code} (${job.data.error_detail})`);
    }
    if (!Number.isInteger(job.data.bulletin_id)) {
      throw new Error(`Bulletin job ${accepted.data.id} succeeded without a bulletin_id`);
    }
    return this.api.apiCall('GET', `/bulletins/${job.data.bulletin_id}`);
  }

  /** @returns {boolean} Cached FFmpeg availability. */
  isFFmpegAvailable() {
    if (this._ffmpegAvailable === null) {
      try {
        execFileSync('ffmpeg', ['-version'], { stdio: 'ignore' });
        this._ffmpegAvailable = true;
      } catch (error) {
        this._ffmpegAvailable = false;
        this._ffmpegFailure = commandErrorMessage(error);
        console.warn(`ffmpeg is not available: ${this._ffmpegFailure}`);
      }
    }
    return this._ffmpegAvailable;
  }

  requireFFmpeg() {
    if (!this.isFFmpegAvailable()) {
      throw new Error(`Fixture requires FFmpeg, but ffmpeg is not available: ${this._ffmpegFailure || 'availability check failed'}`);
    }
  }

  fixtureResponse(response, method, endpoint, expectedStatus = 201, requireID = true) {
    if (response.status !== expectedStatus || (requireID && !response.data?.id)) {
      throw new Error(`Fixture ${method} ${endpoint} failed: HTTP ${response.status}; body ${JSON.stringify(response.data)}`);
    }
    return response.data;
  }

  /**
   * @param {string} outputPath
   * @param {number} [duration=3]
   * @param {number} [frequency=440]
   * @returns {boolean}
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
      this._audioCreationFailure = commandErrorMessage(error);
      console.warn(`Failed to create test audio file ${outputPath}: ${this._audioCreationFailure}`);
      return false;
    }
  }

  /** @param {string} filePath */
  cleanupTempFile(filePath) {
    try {
      fsSync.unlinkSync(filePath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.warn(`Failed to clean up temporary file ${filePath}: ${error.message}`);
      }
    }
  }

  /**
   * @param {string} baseName
   * @returns {string}
   */
  uniqueName(baseName) {
    return `${baseName}_${Date.now()}_${process.pid}`;
  }

  /**
   * @param {Object} resourceManager
   * @param {string} name
   * @param {number} [maxStories]
   * @param {number} [pauseSeconds]
   * @returns {Promise<{id: number, name: string}>}
   */
  async createStation(resourceManager, name, maxStories = 4, pauseSeconds = 2.0) {
    const uniqueName = this.uniqueName(name);

    const response = await this.api.apiCall('POST', '/stations', {
      name: uniqueName,
      max_stories_per_block: maxStories,
      pause_seconds: pauseSeconds
    });

    const { id } = this.fixtureResponse(response, 'POST', '/stations');
    resourceManager.track('stations', id);
    return { id, name: uniqueName };
  }

  /**
   * @param {Object} resourceManager
   * @param {string} name
   * @returns {Promise<{id: number, name: string}>}
   */
  async createVoice(resourceManager, name) {
    const uniqueName = this.uniqueName(name);

    const response = await this.api.apiCall('POST', '/voices', {
      name: uniqueName
    });

    const { id } = this.fixtureResponse(response, 'POST', '/voices');
    resourceManager.track('voices', id);
    return { id, name: uniqueName };
  }

  /**
   * @param {Object} resourceManager
   * @param {Object} data
   * @returns {Promise<{id: number}>}
   */
  async createStory(resourceManager, data) {
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
      metadata: data.metadata || null
    };

    const response = await this.api.apiCall('POST', '/stories', storyData);

    const { id } = this.fixtureResponse(response, 'POST', '/stories');
    resourceManager.track('stories', id);
    return { id };
  }

  /**
   * @param {Object} resourceManager
   * @param {Object} data
   * @returns {Promise<{id: number}>}
   */
  async createStoryWithAudio(resourceManager, data) {
    this.requireFFmpeg();

    const audioFile = `/tmp/test_story_${Date.now()}.wav`;

    try {
      if (!this.createTestAudioFile(audioFile, 3, 220)) {
        throw new Error(`FFmpeg could not create story audio fixture: ${this._audioCreationFailure || audioFile}`);
      }
      const story = await this.createStory(resourceManager, data);

      const uploadResponse = await this.api.uploadFile(
        `/stories/${story.id}/audio`,
        {},
        audioFile,
        'audio'
      );

      this.fixtureResponse(uploadResponse, 'POST', `/stories/${story.id}/audio`, 201, false);
      return story;
    } finally {
      this.cleanupTempFile(audioFile);
    }
  }

  /**
   * @param {Object} resourceManager
   * @param {Object} data
   * @returns {Promise<{id: number}>}
   */
  async createStoryWithReadyAudio(resourceManager, data) {
    const story = await this.createStoryWithAudio(resourceManager, data);
    const audioReady = await this.waitForStoryAudio(story.id);
    if (!audioReady) throw new Error(`Fixture GET /stories/${story.id}: audio did not become ready within 10 seconds`);
    return story;
  }

  /**
   * Fails fast when the fixture cannot be prepared.
   * @param {Object} resourceManager
   * @param {Object} data
   * @returns {Promise<{id: number}>}
   */
  async requireStoryWithReadyAudio(resourceManager, data) {
    const story = await this.createStoryWithReadyAudio(resourceManager, data);
    if (!story) {
      throw new Error(`Failed to create ready story audio fixture: ${data.title || 'untitled story'}`);
    }
    return story;
  }

  /**
   * Throws if any fixture fails; created resources remain tracked for cleanup.
   * @param {Object} resourceManager
   * @param {string|number} voiceId
   * @param {Object[]} stories
   * @returns {Promise<Array<{id: number}>>}
   */
  async createStoriesWithReadyAudio(resourceManager, voiceId, stories) {
    const safeVoiceId = parseSafeInteger(voiceId, 'voice ID');
    const created = [];

    for (const story of stories) {
      const createdStory = await this.createStoryWithReadyAudio(resourceManager, {
        voice_id: safeVoiceId,
        weekdays: 127,
        status: 'active',
        ...story
      });

      created.push(createdStory);
    }

    return created;
  }

  /**
   * @param {Object} resourceManager
   * @param {string|number} voiceId
   * @param {Object[]} stories
   * @returns {Promise<Array<{id: number}>>}
   */
  async requireStoriesWithReadyAudio(resourceManager, voiceId, stories) {
    const created = await this.createStoriesWithReadyAudio(resourceManager, voiceId, stories);
    if (!created) {
      throw new Error(`Failed to create ready story audio fixtures for voice ${voiceId}`);
    }
    return created;
  }

  /**
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {number} [mixPoint]
   * @returns {Promise<{id: number}>}
   */
  async createStationVoice(resourceManager, stationId, voiceId, mixPoint = 3.0) {
    const response = await this.api.apiCall('POST', '/station-voices', {
      station_id: parseSafeInteger(stationId, 'station ID'),
      voice_id: parseSafeInteger(voiceId, 'voice ID'),
      mix_point: parseFiniteNumber(mixPoint, 'mix point')
    });

    const { id } = this.fixtureResponse(response, 'POST', '/station-voices');
    resourceManager.track('stationVoices', id);
    return { id };
  }

  /**
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {number} [mixPoint]
   * @returns {Promise<{id: number}>}
   */
  async createStationVoiceWithJingle(resourceManager, stationId, voiceId, mixPoint = 3.0) {
    const safeStationId = parseSafeInteger(stationId, 'station ID');
    const safeVoiceId = parseSafeInteger(voiceId, 'voice ID');

    this.requireFFmpeg();

    const jingleFile = `/tmp/test_jingle_${safeStationId}_${safeVoiceId}_${Date.now()}.wav`;

    try {
      if (!this.createTestAudioFile(jingleFile, 5, 440)) {
        throw new Error(`FFmpeg could not create jingle fixture: ${this._audioCreationFailure || jingleFile}`);
      }
      const stationVoice = await this.createStationVoice(resourceManager, safeStationId, safeVoiceId, mixPoint);

      const uploadResponse = await this.api.uploadFile(
        `/station-voices/${stationVoice.id}/audio`,
        {},
        jingleFile,
        'jingle'
      );

      this.fixtureResponse(uploadResponse, 'POST', `/station-voices/${stationVoice.id}/audio`, 201, false);

      return stationVoice;
    } finally {
      this.cleanupTempFile(jingleFile);
    }
  }

  /**
   * Creates the complete fixture required to generate a bulletin.
   * @param {Object} resourceManager
   * @param {Object} [options]
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

    const story = await this.requireStoryWithReadyAudio(resourceManager, storyData);

    return { station, voice, stationVoice, story };
  }

  /**
   * @param {string|number} stationId
   * @param {Object} [queryParams]
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

    const contentType = response.headers['content-type'] || '';
    // Errors are problem+json; decode them so tests can assert on the body.
    const data = contentType.includes('json')
      ? JSON.parse(Buffer.from(response.data).toString('utf8'))
      : response.data;

    return {
      status: response.status,
      data,
      headers: response.headers,
      contentType
    };
  }
}

module.exports = TestHelpers;
