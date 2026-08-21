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

  // General utilities

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
      if (response.status === 200 && response.data.audio_url) {
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
      if (response.status !== 200) {
        throw new Error(`Bulletin job ${jobId} poll returned HTTP ${response.status}`);
      }
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
   * @param {Object} [body]
   * @returns {Promise<Object>}
   */
  async generateBulletin(stationId, body = {}) {
    const accepted = await this.api.apiCall('POST', `/stations/${stationId}/bulletins`, body);
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

  // FFmpeg

  /** @returns {boolean} Cached FFmpeg availability. */
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
      console.warn(`Failed to create test audio file ${outputPath}: ${commandErrorMessage(error)}`);
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

  // Resource creation

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
   * @returns {Promise<{id: number, name: string}|null>}
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
   * @param {Object} resourceManager
   * @param {string} name
   * @returns {Promise<{id: number, name: string}|null>}
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
   * @param {Object} resourceManager
   * @param {Object} data
   * @param {number[]} targetStations
   * @returns {Promise<{id: number}|null>}
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
   * @param {Object} resourceManager
   * @param {Object} data
   * @param {number[]} targetStations
   * @returns {Promise<{id: number}|null>}
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
   * @param {Object} resourceManager
   * @param {Object} data
   * @param {number[]} targetStations
   * @returns {Promise<{id: number}|null>}
   */
  async createStoryWithReadyAudio(resourceManager, data, targetStations) {
    const story = await this.createStoryWithAudio(resourceManager, data, targetStations);
    if (!story) {
      return null;
    }

    const audioReady = await this.waitForStoryAudio(story.id);
    return audioReady ? story : null;
  }

  /**
   * Fails fast when the fixture cannot be prepared.
   * @param {Object} resourceManager
   * @param {Object} data
   * @param {number[]} targetStations
   * @returns {Promise<{id: number}>}
   */
  async requireStoryWithReadyAudio(resourceManager, data, targetStations) {
    const story = await this.createStoryWithReadyAudio(resourceManager, data, targetStations);
    if (!story) {
      throw new Error(`Failed to create ready story audio fixture: ${data.title || 'untitled story'}`);
    }
    return story;
  }

  /**
   * Returns null, never a partial result.
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {Object[]} stories
   * @returns {Promise<Array<{id: number}>|null>}
   */
  async createStationStoriesWithReadyAudio(resourceManager, stationId, voiceId, stories) {
    const safeStationId = parseSafeInteger(stationId, 'station ID');
    const safeVoiceId = parseSafeInteger(voiceId, 'voice ID');
    const created = [];

    for (const story of stories) {
      const createdStory = await this.createStoryWithReadyAudio(resourceManager, {
        voice_id: safeVoiceId,
        weekdays: 127,
        status: 'active',
        ...story
      }, [safeStationId]);

      if (!createdStory) {
        return null;
      }

      created.push(createdStory);
    }

    return created;
  }

  /**
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {Object[]} stories
   * @returns {Promise<Array<{id: number}>>}
   */
  async requireStationStoriesWithReadyAudio(resourceManager, stationId, voiceId, stories) {
    const created = await this.createStationStoriesWithReadyAudio(resourceManager, stationId, voiceId, stories);
    if (!created) {
      throw new Error(`Failed to create ready story audio fixtures for station ${stationId} and voice ${voiceId}`);
    }
    return created;
  }

  /**
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {number} [mixPoint]
   * @returns {Promise<{id: number}|null>}
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
   * @param {Object} resourceManager
   * @param {string|number} stationId
   * @param {string|number} voiceId
   * @param {number} [mixPoint]
   * @returns {Promise<{id: number}|null>}
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

      const uploadResponse = await this.api.uploadFile(
        `/station-voices/${stationVoice.id}/audio`,
        {},
        jingleFile,
        'jingle'
      );

      if (uploadResponse.status !== 201) {
        console.warn(`Failed to upload jingle for station-voice ${stationVoice.id}: HTTP ${uploadResponse.status}`);
        return null;
      }

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

    const story = await this.requireStoryWithReadyAudio(resourceManager, storyData, [station.id]);

    return { station, voice, stationVoice, story };
  }

  // Public endpoints

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

    return {
      status: response.status,
      data: response.data,
      headers: response.headers,
      contentType: response.headers['content-type']
    };
  }
}

module.exports = TestHelpers;
