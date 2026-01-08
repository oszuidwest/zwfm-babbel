/**
 * Babbel validation tests.
 * Comprehensive validation testing for all API endpoints.
 * Tests field validation, data types, boundaries, business rules, and input sanitization.
 */

describe('Validation', () => {
  // Track created resources for cleanup
  const createdResources = {
    stations: [],
    voices: [],
    stories: [],
    users: [],
    stationVoices: []
  };

  afterAll(async () => {
    // Clean up stories first (depends on voices/stations)
    for (const id of createdResources.stories) {
      try { await global.api.apiCall('DELETE', `/stories/${id}`); } catch {}
    }
    // Clean up station-voices
    for (const id of createdResources.stationVoices) {
      try { await global.api.apiCall('DELETE', `/station-voices/${id}`); } catch {}
    }
    // Clean up stations
    for (const id of createdResources.stations) {
      try { await global.api.apiCall('DELETE', `/stations/${id}`); } catch {}
    }
    // Clean up voices
    for (const id of createdResources.voices) {
      try { await global.api.apiCall('DELETE', `/voices/${id}`); } catch {}
    }
    // Clean up users
    for (const id of createdResources.users) {
      try { await global.api.apiCall('DELETE', `/users/${id}`); } catch {}
    }
  });

  describe('Station Field Validation', () => {
    test('rejects empty data', async () => {
      const response = await global.api.apiCall('POST', '/stations', {});
      expect(response.status).toBe(422);
    });

    test('rejects missing name', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects null name', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: null,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty string name', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: '',
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects whitespace-only name', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: '   ',
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Station Data Type Validation', () => {
    test('rejects string max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 'invalid',
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects negative max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: -1,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects zero max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 0,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects float max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 5.5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects string pause_seconds', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 5,
        pause_seconds: 'invalid'
      });
      expect(response.status).toBe(422);
    });

    test('rejects negative pause_seconds', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 5,
        pause_seconds: -1.0
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Station Boundary Validation', () => {
    test('rejects very large max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 1000000,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects very large pause_seconds', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Test Station',
        max_stories_per_block: 5,
        pause_seconds: 999999.99
      });
      expect(response.status).toBe(422);
    });

    test('rejects very long station name', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'A'.repeat(300),
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Station Unique Constraint', () => {
    test('rejects duplicate station name', async () => {
      const uniqueName = `UniqueTest_${Date.now()}`;

      // Create first station
      const createResponse = await global.api.apiCall('POST', '/stations', {
        name: uniqueName,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect(createResponse.status).toBe(201);
      const stationId = global.api.parseJsonField(createResponse.data, 'id');
      if (stationId) createdResources.stations.push(stationId);

      // Try duplicate
      const duplicateResponse = await global.api.apiCall('POST', '/stations', {
        name: uniqueName,
        max_stories_per_block: 3,
        pause_seconds: 1.5
      });

      expect(duplicateResponse.status).toBe(409);
    });
  });

  describe('Voice Validation', () => {
    test('rejects empty voice data', async () => {
      const response = await global.api.apiCall('POST', '/voices', {});
      expect(response.status).toBe(422);
    });

    test('rejects missing voice name', async () => {
      const response = await global.api.apiCall('POST', '/voices', {
        description: 'Test voice'
      });
      expect(response.status).toBe(422);
    });

    test('rejects null voice name', async () => {
      const response = await global.api.apiCall('POST', '/voices', { name: null });
      expect(response.status).toBe(422);
    });

    test('rejects empty voice name', async () => {
      const response = await global.api.apiCall('POST', '/voices', { name: '' });
      expect(response.status).toBe(422);
    });

    test('rejects whitespace voice name', async () => {
      const response = await global.api.apiCall('POST', '/voices', { name: '   ' });
      expect(response.status).toBe(422);
    });

    test('rejects very long voice name', async () => {
      const response = await global.api.apiCall('POST', '/voices', { name: 'A'.repeat(300) });
      expect(response.status).toBe(422);
    });
  });

  describe('User Validation', () => {
    test('rejects empty user data', async () => {
      const response = await global.api.apiCall('POST', '/users', {});
      expect(response.status).toBe(422);
    });

    test('rejects missing username', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        full_name: 'Test User',
        password: 'test1234',
        role: 'viewer'
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty username', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: '',
        full_name: 'Test User',
        password: 'test1234',
        role: 'viewer'
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing password', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'testuser',
        full_name: 'Test User',
        role: 'viewer'
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty password', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'testuser',
        full_name: 'Test User',
        password: '',
        role: 'viewer'
      });
      expect(response.status).toBe(422);
    });

    test('rejects invalid role', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'testuser',
        full_name: 'Test User',
        password: 'test1234',
        role: 'invalid'
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing role', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'testuser',
        full_name: 'Test User',
        password: 'test1234'
      });
      expect(response.status).toBe(422);
    });
  });

  describe('User Unique Constraints', () => {
    test('rejects duplicate username', async () => {
      const uniqueUsername = `uniquetest${Date.now()}`;

      // Create first user
      const createResponse = await global.api.apiCall('POST', '/users', {
        username: uniqueUsername,
        full_name: 'Unique Test User',
        password: 'test1234',
        role: 'viewer'
      });

      expect(createResponse.status).toBe(201);
      const userId = global.api.parseJsonField(createResponse.data, 'id');
      if (userId) createdResources.users.push(userId);

      // Try duplicate
      const duplicateResponse = await global.api.apiCall('POST', '/users', {
        username: uniqueUsername,
        full_name: 'Another User',
        password: 'test4567',
        role: 'editor'
      });

      expect(duplicateResponse.status).toBe(409);
    });
  });

  describe('Story Validation', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      // Create station for target_stations
      const stationResponse = await global.api.apiCall('POST', '/stations', {
        name: `ValidationTestStation_${Date.now()}`,
        max_stories_per_block: 4,
        pause_seconds: 2.0
      });
      stationId = global.api.parseJsonField(stationResponse.data, 'id');
      if (stationId) createdResources.stations.push(stationId);

      // Create voice
      const voiceResponse = await global.api.apiCall('POST', '/voices', {
        name: `TestVoice_${Date.now()}`
      });
      voiceId = global.api.parseJsonField(voiceResponse.data, 'id');
      if (voiceId) createdResources.voices.push(voiceId);
    });

    test('rejects empty story data', async () => {
      const response = await global.api.apiCall('POST', '/stories', {});
      expect(response.status).toBe(422);
    });

    test('rejects missing title', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty title', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: '',
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing text', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty text', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        text: '',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing voice_id (required field)', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: `Missing Voice Test ${Date.now()}`,
        text: 'Test content',
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects invalid voice_id', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        text: 'Test content',
        voice_id: 99999,
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects empty target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        target_stations: [],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects invalid station ID in target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test Story',
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        target_stations: [99999],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Story Boundary Validation', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      const stationResponse = await global.api.apiCall('POST', '/stations', {
        name: `BoundaryTestStation_${Date.now()}`,
        max_stories_per_block: 4,
        pause_seconds: 2.0
      });
      stationId = global.api.parseJsonField(stationResponse.data, 'id');
      if (stationId) createdResources.stations.push(stationId);

      const voiceResponse = await global.api.apiCall('POST', '/voices', {
        name: `BoundaryTestVoice_${Date.now()}`
      });
      voiceId = global.api.parseJsonField(voiceResponse.data, 'id');
      if (voiceId) createdResources.voices.push(voiceId);
    });

    test('rejects title exceeding 500 chars', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'A'.repeat(501),
        text: 'Test',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects text exceeding limit', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test',
        text: 'C'.repeat(70000),
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Story Date Validation', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      const stationResponse = await global.api.apiCall('POST', '/stations', {
        name: `DateTestStation_${Date.now()}`,
        max_stories_per_block: 4,
        pause_seconds: 2.0
      });
      stationId = global.api.parseJsonField(stationResponse.data, 'id');
      if (stationId) createdResources.stations.push(stationId);

      const voiceResponse = await global.api.apiCall('POST', '/voices', {
        name: `DateTestVoice_${Date.now()}`
      });
      voiceId = global.api.parseJsonField(voiceResponse.data, 'id');
      if (voiceId) createdResources.voices.push(voiceId);
    });

    test('rejects invalid start date', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test',
        text: 'Test',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        start_date: 'invalid-date',
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects invalid end date', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test',
        text: 'Test',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        end_date: 'invalid-date',
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });

    test('rejects end date before start date', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Test',
        text: 'Test',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        start_date: '2024-12-31',
        end_date: '2024-01-01',
        status: 'active',
        weekdays: 127
      });
      expect(response.status).toBe(422);
    });
  });

  describe('Station-Voice Validation', () => {
    test('rejects empty station-voice data', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {});
      expect(response.status).toBe(422);
    });

    test('rejects missing station_id', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        voice_id: 1,
        mix_point: 3.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects missing voice_id', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 1,
        mix_point: 3.0
      });
      expect(response.status).toBe(422);
    });

    test('rejects invalid station_id', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 99999,
        voice_id: 1,
        mix_point: 3.0
      });
      expect(response.status).toBe(404);
    });

    test('rejects invalid voice_id', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 1,
        voice_id: 99999,
        mix_point: 3.0
      });
      expect(response.status).toBe(404);
    });

    test('rejects negative mix_point', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 1,
        voice_id: 1,
        mix_point: -1.0
      });
      expect(response.status).toBe(422);
    });
  });

  describe('SQL Injection Prevention', () => {
    const sqlPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "'; SELECT * FROM users; --",
      "' UNION SELECT password FROM users --",
      "admin'--",
      "admin' OR '1'='1' --"
    ];

    test.each(sqlPayloads)('safely handles SQL payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      // Should be rejected (422) or safely handled (201/409)
      expect([201, 409, 422]).toContain(response.status);

      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdResources.stations.push(stationId);
      }
    });
  });

  describe('XSS Prevention', () => {
    const xssPayloads = [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      "javascript:alert('xss')",
      "<svg/onload=alert('xss')>",
      "'><script>alert('xss')</script>"
    ];

    test.each(xssPayloads)('safely handles XSS payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect([201, 409, 422]).toContain(response.status);

      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdResources.stations.push(stationId);
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    const pathPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ];

    test.each(pathPayloads)('safely handles path traversal payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect([201, 409, 422]).toContain(response.status);

      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdResources.stations.push(stationId);
      }
    });
  });

  describe('Audio File Upload Validation', () => {
    test('allows story creation without audio (JSON API)', async () => {
      // Create station inline
      const stationResponse = await global.api.apiCall('POST', '/stations', {
        name: `AudioUploadStation_${Date.now()}`,
        max_stories_per_block: 4,
        pause_seconds: 2.0
      });
      expect(stationResponse.status).toBe(201);
      const stationId = global.api.parseJsonField(stationResponse.data, 'id');
      if (stationId) createdResources.stations.push(stationId);

      // Create voice inline
      const voiceResponse = await global.api.apiCall('POST', '/voices', {
        name: `AudioUploadVoice_${Date.now()}`
      });
      expect(voiceResponse.status).toBe(201);
      const voiceId = global.api.parseJsonField(voiceResponse.data, 'id');
      if (voiceId) createdResources.voices.push(voiceId);

      // Create story without audio
      const today = new Date();
      const nextYear = new Date(today.getFullYear() + 1, today.getMonth(), today.getDate());
      const storyData = {
        title: `No File Test ${Date.now()}`,
        text: 'Test content',
        voice_id: parseInt(voiceId, 10),
        target_stations: [parseInt(stationId, 10)],
        status: 'active',
        weekdays: 127,
        start_date: today.toISOString().split('T')[0],
        end_date: nextYear.toISOString().split('T')[0]
      };
      const response = await global.api.apiCall('POST', '/stories', storyData);

      expect(response.status).toBe(201);
      const storyId = global.api.parseJsonField(response.data, 'id');
      if (storyId) createdResources.stories.push(storyId);
    });
  });

  describe('Business Rule Validation', () => {
    test('accepts minimum reasonable values', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: `Min Test ${Date.now()}`,
        max_stories_per_block: 1,
        pause_seconds: 0.1
      });

      expect(response.status).toBe(201);
      const stationId = global.api.parseJsonField(response.data, 'id');
      if (stationId) createdResources.stations.push(stationId);
    });
  });
});
