/**
 * Babbel station-voices tests.
 * Tests station-voice relationship management and jingle functionality.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const fs = require('fs');
const { execSync } = require('child_process');
const stationVoicesSchema = require('../lib/schemas/station-voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');

describe('Station-Voices', () => {
  // Setup function creates dependencies and returns data to merge with createValidData
  const createDependencies = async () => {
    const station = await global.helpers.createStation(global.resources, `SVDep_${Date.now()}`);
    const voice = await global.helpers.createVoice(global.resources, `SVDep_${Date.now()}`);
    return {
      station_id: parseInt(station.id, 10),
      voice_id: parseInt(voice.id, 10)
    };
  };

  // Setup function for query tests - creates multiple station-voices for testing
  const setupQueryTestData = async () => {
    const testData = [
      { station: 'QueryStation1', voice: 'QueryVoice1', mix: 1.0 },
      { station: 'QueryStation2', voice: 'QueryVoice2', mix: 2.5 },
      { station: 'QueryStation3', voice: 'QueryVoice3', mix: 3.0 }
    ];

    const ids = [];
    for (const data of testData) {
      const station = await global.helpers.createStation(global.resources, data.station);
      const voice = await global.helpers.createVoice(global.resources, data.voice);

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        voice_id: parseInt(voice.id, 10),
        mix_point: data.mix
      });

      if (response.status === 201) {
        global.resources.track('stationVoices', response.data.id);
        ids.push(response.data.id);
      }
    }
    return ids;
  };

  // Generate standard tests using generators
  generateCrudTests(stationVoicesSchema, createDependencies);
  generateQueryTests(stationVoicesSchema, setupQueryTestData);
  generateValidationTests(stationVoicesSchema, createDependencies);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to station-voice behavior that can't be generated

  describe('Duplicate Detection', () => {
    test('when creating duplicate station-voice pair, then returns 409', async () => {
      // Arrange: Create a station-voice
      const station = await global.helpers.createStation(global.resources, 'DupStation');
      const voice = await global.helpers.createVoice(global.resources, 'DupVoice');
      const data = {
        station_id: parseInt(station.id, 10),
        voice_id: parseInt(voice.id, 10),
        mix_point: 2.5
      };

      const first = await global.api.apiCall('POST', '/station-voices', data);
      expect(first.status).toBe(201);
      global.resources.track('stationVoices', first.data.id);

      // Act: Try to create duplicate
      const duplicate = await global.api.apiCall('POST', '/station-voices', data);

      // Assert
      expect(duplicate.status).toBe(409);
    });
  });

  describe('Station-Voice Audio', () => {
    const testAudio = '/tmp/test_jingle.wav';

    beforeAll(async () => {
      // Arrange: Create test audio file if ffmpeg available
      if (!fs.existsSync(testAudio)) {
        try {
          execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 1 -f wav "${testAudio}" 2>/dev/null`, { stdio: 'ignore' });
        } catch {
          // ffmpeg not available
        }
      }
    });

    test('when uploading jingle, then attached', async () => {
      // Skip if ffmpeg not available
      if (!fs.existsSync(testAudio)) {
        console.log('Skipping audio test - ffmpeg not available');
        return;
      }

      // Arrange
      const station = await global.helpers.createStation(global.resources, 'AudioTestStation');
      const voice = await global.helpers.createVoice(global.resources, 'AudioTestVoice');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        voice_id: parseInt(voice.id, 10),
        mix_point: 1.5
      });
      expect(response.status).toBe(201);
      global.resources.track('stationVoices', response.data.id);

      // Act
      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${response.data.id}/audio`,
        {},
        testAudio,
        'jingle'
      );

      // Assert
      expect(uploadResponse.status).toBe(201);
    });

    test('when fetching, then audio fields present', async () => {
      // Arrange
      const station = await global.helpers.createStation(global.resources, 'AudioFieldsStation');
      const voice = await global.helpers.createVoice(global.resources, 'AudioFieldsVoice');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        voice_id: parseInt(voice.id, 10),
        mix_point: 2.0
      });
      expect(response.status).toBe(201);
      global.resources.track('stationVoices', response.data.id);

      // Act
      const getResponse = await global.api.apiCall('GET', `/station-voices/${response.data.id}`);

      // Assert
      expect(getResponse.status).toBe(200);
      expect(getResponse.data).toHaveProperty('audio_url');
      expect(typeof getResponse.data.audio_url).toBe('string');
      expect(getResponse.data).toHaveProperty('audio_file');
    });
  });

  describe('Foreign Key Validation', () => {
    test('when station_id invalid, then returns error', async () => {
      // Arrange
      const voice = await global.helpers.createVoice(global.resources, 'FKValidationVoice');

      // Act
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 999999,
        voice_id: parseInt(voice.id, 10),
        mix_point: 2.0
      });

      // Assert
      expect([404, 422]).toContain(response.status);
    });

    test('when voice_id invalid, then returns error', async () => {
      // Arrange
      const station = await global.helpers.createStation(global.resources, 'FKValidationStation');

      // Act
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        voice_id: 999999,
        mix_point: 2.0
      });

      // Assert
      expect([404, 422]).toContain(response.status);
    });
  });
});
