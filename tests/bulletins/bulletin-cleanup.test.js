/**
 * Babbel bulletin cleanup tests.
 * Tests that purged bulletins behave correctly: no audio_url, metadata preserved,
 * latest endpoint skips purged, automation regenerates after purge.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const fsSync = require('fs');
const path = require('path');

const TestHelpers = require('../lib/TestHelpers');
const { createMySQLExecutor, sqlInteger } = require('../lib/MySQLHelper');

describe('Bulletin Cleanup', () => {
  const automationKey = TestHelpers.AUTOMATION_KEY;

  const audioDir = path.join(__dirname, '../../audio');
  const mysql = createMySQLExecutor();

  let testStationId = null;
  let purgedBulletinId = null;
  let unpurgedBulletinId = null;

  const markBulletinPurged = (bulletinId) => {
    const id = sqlInteger(bulletinId, 'bulletin ID');

    mysql.execSQL(`UPDATE bulletins SET file_purged_at = NOW() WHERE id = ${id}`);

    const result = mysql.execSQL(`SELECT audio_file FROM bulletins WHERE id = ${id}`);
    const lines = result.trim().split('\n');
    if (lines.length >= 2) {
      const filename = lines[1].trim();
      if (filename) {
        const filePath = path.join(audioDir, 'output', filename);
        try {
          fsSync.unlinkSync(filePath);
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw new Error(`Failed to delete purged bulletin audio file ${filePath}: ${error.message}`);
          }
        }
      }
    }
  };

  beforeAll(async () => {
    const { station } = await global.helpers.createBroadcastFixture(global.resources, {
      stationName: 'Cleanup Test Station',
      voiceName: 'Cleanup Test Voice',
      storyTitle: 'CleanupTestStory',
      storyText: 'Story for testing bulletin cleanup behavior.',
      maxStories: 3,
      pauseSeconds: 2.0
    });
    testStationId = station.id;

    // Generate first bulletin
    const bulletin1 = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
    expect(bulletin1.status).toBe(200);
    purgedBulletinId = bulletin1.data.id;
    global.resources.track('bulletins', purgedBulletinId);

    // Small delay for different timestamps
    await global.helpers.sleep(1000);

    // Generate second bulletin
    const bulletin2 = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
    expect(bulletin2.status).toBe(200);
    unpurgedBulletinId = bulletin2.data.id;
    global.resources.track('bulletins', unpurgedBulletinId);

    // Mark the first (older) bulletin as purged
    markBulletinPurged(purgedBulletinId);
  });

  describe('Purged Bulletin Properties', () => {
    test('when bulletin is purged, then has no audio_url but has file_purged_at', async () => {
      // Act
      const purgedResponse = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}`);
      const unpurgedResponse = await global.api.apiCall('GET', `/bulletins/${unpurgedBulletinId}`);

      // Assert: purged bulletin
      expect(purgedResponse.status).toBe(200);
      expect(purgedResponse.data.audio_url).toBeFalsy();
      expect(purgedResponse.data.file_purged_at).toBeTruthy();

      // Assert: unpurged bulletin still has audio_url
      expect(unpurgedResponse.status).toBe(200);
      expect(unpurgedResponse.data.audio_url).toBeTruthy();
      expect(unpurgedResponse.data.file_purged_at).toBeFalsy();
    });

    test('when requesting purged bulletin audio, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}/audio`);

      // Assert
      expect(response.status).toBe(404);
    });

    test('when bulletin is purged, then metadata is preserved', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}`);

      // Assert
      expect(response.status).toBe(200);
      const bulletin = response.data;
      expect(bulletin.id).toBe(purgedBulletinId);
      expect(bulletin.station_id).toBeDefined();
      expect(bulletin.filename).toBeTruthy();
      expect(bulletin.duration_seconds).toBeDefined();
      expect(bulletin.story_count).toBeDefined();
      expect(bulletin.created_at).toBeTruthy();
    });
  });

  describe('Purged Bulletin Listing', () => {
    test('when listing bulletins, then includes both purged and unpurged', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/stations/${testStationId}/bulletins`);

      // Assert
      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      expect(bulletins.length).toBeGreaterThanOrEqual(2);

      const purged = bulletins.find(b => String(b.id) === String(purgedBulletinId));
      const unpurged = bulletins.find(b => String(b.id) === String(unpurgedBulletinId));

      expect(purged).toBeDefined();
      expect(purged.audio_url).toBeFalsy();
      expect(purged.file_purged_at).toBeTruthy();

      expect(unpurged).toBeDefined();
      expect(unpurged.audio_url).toBeTruthy();
      expect(unpurged.file_purged_at).toBeFalsy();
    });

    test('when requesting latest bulletin, then skips purged', async () => {
      // Arrange: generate a third bulletin and purge it (making it the newest)
      const thirdResponse = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
      expect(thirdResponse.status).toBe(200);
      const thirdBulletinId = thirdResponse.data.id;
      global.resources.track('bulletins', thirdBulletinId);

      markBulletinPurged(thirdBulletinId);

      // Act
      const latestResponse = await global.api.apiCall('GET', `/stations/${testStationId}/bulletins?latest=true`);

      // Assert
      expect(latestResponse.status).toBe(200);
      const latestId = String(latestResponse.data.id);

      // Should not return either purged bulletin
      expect(latestId).not.toBe(String(thirdBulletinId));
      expect(latestId).not.toBe(String(purgedBulletinId));
      expect(latestResponse.data.audio_url).toBeTruthy();
    });
  });

  describe('Automation After Purge', () => {
    test('when all bulletins purged, then automation regenerates', async () => {
      // Arrange: create a separate station to avoid interference
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'Automation Purge Test',
        voiceName: 'Automation Purge Voice',
        storyTitle: 'AutomationPurgeStory',
        storyText: 'Story for testing automation after purge.',
        maxStories: 3,
        pauseSeconds: 2.0
      });

      // Generate initial bulletin via automation
      const initialResponse = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '0'
      });
      expect(initialResponse.status).toBe(200);
      const initialBulletinId = initialResponse.headers['x-bulletin-id'];

      // Purge it
      markBulletinPurged(initialBulletinId);

      // Act: request again - should generate fresh since no unpurged bulletins exist
      const afterPurgeResponse = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '3600'
      });

      // Assert
      expect(afterPurgeResponse.status).toBe(200);
      expect(afterPurgeResponse.headers['x-bulletin-cached']).toBe('false');
      expect(afterPurgeResponse.headers['x-bulletin-id']).not.toBe(initialBulletinId);
      expect(afterPurgeResponse.contentType).toContain('audio/wav');
    });
  });

  describe('Purge Filtering', () => {
    test('when filtering by purged status, then returns correct results', async () => {
      // Act
      const response = await global.api.apiCall('GET',
        `/stations/${testStationId}/bulletins?filter[file_purged_at][ne]=null`
      );

      // Assert
      expect(response.status).toBe(200);
      const purgedBulletins = response.data.data || [];

      // All returned bulletins should have file_purged_at set
      for (const b of purgedBulletins) {
        expect(b.file_purged_at).toBeTruthy();
      }
    });
  });
});
