const fs = require('fs');
const os = require('os');
const path = require('path');

const OpenApiContractValidator = require('../lib/OpenApiContractValidator');
const TestHelpers = require('../lib/TestHelpers');

const SPEC_PATH = path.join(__dirname, '../../openapi.yaml');

describe('OpenAPI Contract', () => {
  let validator;
  let ctx;
  const scenarios = createScenarios();

  beforeAll(async () => {
    validator = await OpenApiContractValidator.fromFile(SPEC_PATH);
    ctx = await createContractContext();
  });

  test('when contract suite is loaded, then every OpenAPI operation is covered', () => {
    const documentedOperations = validator.getOperationKeys();
    const coveredOperations = [...new Set(scenarios.map(s => validator.operationKey(s.method, s.operationPath)))].sort();

    expect(coveredOperations).toEqual(documentedOperations);
  });

  test.each(scenarios.map(scenario => [scenario.name, scenario]))(
    'when calling %s, then response matches OpenAPI',
    async (_name, scenario) => {
      await scenario.run();
    }
  );

  function createScenarios() {
    return [
      {
        name: 'GET /health',
        method: 'GET',
        operationPath: '/health',
        run: () => rawCall('GET', '/health', `${global.api.apiBase}/health`)
      },
      {
        name: 'GET /public/stations/{id}/bulletin.wav',
        method: 'GET',
        operationPath: '/public/stations/{id}/bulletin.wav',
        run: () => rawCall(
          'GET',
          '/public/stations/{id}/bulletin.wav',
          `${global.api.apiBase}/public/stations/${ctx.station.id}/bulletin.wav?key=${TestHelpers.AUTOMATION_KEY}&max_age=3600`,
          { responseType: 'arraybuffer' }
        )
      },
      {
        name: 'GET /api/v1/auth/config',
        method: 'GET',
        operationPath: '/api/v1/auth/config',
        run: () => apiCall('GET', '/api/v1/auth/config', '/auth/config')
      },
      {
        name: 'POST /api/v1/sessions',
        method: 'POST',
        operationPath: '/api/v1/sessions',
        run: () => apiCall('POST', '/api/v1/sessions', '/sessions', {
          username: 'admin',
          password: 'admin'
        })
      },
      {
        name: 'GET /api/v1/auth/oauth',
        method: 'GET',
        operationPath: '/api/v1/auth/oauth',
        run: () => rawCall('GET', '/api/v1/auth/oauth', `${global.api.apiUrl}/auth/oauth`, { maxRedirects: 0 })
      },
      {
        name: 'GET /api/v1/auth/oauth/callback',
        method: 'GET',
        operationPath: '/api/v1/auth/oauth/callback',
        run: () => rawCall(
          'GET',
          '/api/v1/auth/oauth/callback',
          `${global.api.apiUrl}/auth/oauth/callback?state=contract&code=contract`,
          { maxRedirects: 0 }
        )
      },
      {
        name: 'GET /api/v1/sessions/current',
        method: 'GET',
        operationPath: '/api/v1/sessions/current',
        run: () => apiCall('GET', '/api/v1/sessions/current', '/sessions/current')
      },
      {
        name: 'DELETE /api/v1/sessions/current',
        method: 'DELETE',
        operationPath: '/api/v1/sessions/current',
        run: async () => {
          const response = await apiCall('DELETE', '/api/v1/sessions/current', '/sessions/current');
          const loginResponse = await global.api.apiLogin();
          expect(loginResponse.status).toBe(201);
          return response;
        }
      },
      {
        name: 'GET /api/v1/stations',
        method: 'GET',
        operationPath: '/api/v1/stations',
        run: async () => {
          const response = await apiCall('GET', '/api/v1/stations', '/stations?fields=id,name');
          expectSparseListFields(response, ['id', 'name']);
          return response;
        }
      },
      {
        name: 'POST /api/v1/stations',
        method: 'POST',
        operationPath: '/api/v1/stations',
        run: async () => {
          const body = stationBody('Contract Created Station');
          const response = await apiCall('POST', '/api/v1/stations', '/stations', body);
          global.resources.track('stations', response.data.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/stations/{id}',
        method: 'GET',
        operationPath: '/api/v1/stations/{id}',
        run: () => apiCall('GET', '/api/v1/stations/{id}', `/stations/${ctx.station.id}`)
      },
      {
        name: 'PUT /api/v1/stations/{id}',
        method: 'PUT',
        operationPath: '/api/v1/stations/{id}',
        run: () => apiCall('PUT', '/api/v1/stations/{id}', `/stations/${ctx.station.id}`, stationBody('Contract Updated Station'))
      },
      {
        name: 'DELETE /api/v1/stations/{id}',
        method: 'DELETE',
        operationPath: '/api/v1/stations/{id}',
        run: async () => {
          const station = await global.helpers.createStation(global.resources, 'Contract Delete Station');
          expect(station).not.toBeNull();
          const response = await apiCall('DELETE', '/api/v1/stations/{id}', `/stations/${station.id}`);
          global.resources.untrack('stations', station.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/voices',
        method: 'GET',
        operationPath: '/api/v1/voices',
        run: async () => {
          const response = await apiCall('GET', '/api/v1/voices', '/voices?fields=id,name');
          expectSparseListFields(response, ['id', 'name']);
          return response;
        }
      },
      {
        name: 'POST /api/v1/voices',
        method: 'POST',
        operationPath: '/api/v1/voices',
        run: async () => {
          const response = await apiCall('POST', '/api/v1/voices', '/voices', voiceBody('Contract Created Voice'));
          global.resources.track('voices', response.data.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/voices/{id}',
        method: 'GET',
        operationPath: '/api/v1/voices/{id}',
        run: () => apiCall('GET', '/api/v1/voices/{id}', `/voices/${ctx.voice.id}`)
      },
      {
        name: 'PUT /api/v1/voices/{id}',
        method: 'PUT',
        operationPath: '/api/v1/voices/{id}',
        run: () => apiCall('PUT', '/api/v1/voices/{id}', `/voices/${ctx.voice.id}`, voiceBody('Contract Updated Voice'))
      },
      {
        name: 'DELETE /api/v1/voices/{id}',
        method: 'DELETE',
        operationPath: '/api/v1/voices/{id}',
        run: async () => {
          const voice = await global.helpers.createVoice(global.resources, 'Contract Delete Voice');
          expect(voice).not.toBeNull();
          const response = await apiCall('DELETE', '/api/v1/voices/{id}', `/voices/${voice.id}`);
          global.resources.untrack('voices', voice.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/stories',
        method: 'GET',
        operationPath: '/api/v1/stories',
        run: async () => {
          const response = await apiCall('GET', '/api/v1/stories', '/stories?fields=id,title,status');
          expectSparseListFields(response, ['id', 'title', 'status']);
          return response;
        }
      },
      {
        name: 'POST /api/v1/stories',
        method: 'POST',
        operationPath: '/api/v1/stories',
        run: async () => {
          const response = await apiCall('POST', '/api/v1/stories', '/stories', storyBody('Contract Created Story'));
          global.resources.track('stories', response.data.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/stories/{id}/audio',
        method: 'GET',
        operationPath: '/api/v1/stories/{id}/audio',
        run: () => rawCall(
          'GET',
          '/api/v1/stories/{id}/audio',
          `${global.api.apiUrl}/stories/${ctx.story.id}/audio`,
          { responseType: 'arraybuffer' }
        )
      },
      {
        name: 'POST /api/v1/stories/{id}/audio',
        method: 'POST',
        operationPath: '/api/v1/stories/{id}/audio',
        run: () => uploadCall(
          '/api/v1/stories/{id}/audio',
          `/stories/${ctx.story.id}/audio`,
          'audio',
          { audio: 'contract.wav' }
        )
      },
      {
        name: 'POST /api/v1/stories/{id}/tts',
        method: 'POST',
        operationPath: '/api/v1/stories/{id}/tts',
        run: () => apiCall('POST', '/api/v1/stories/{id}/tts', `/stories/${ctx.story.id}/tts`)
      },
      {
        name: 'GET /api/v1/stories/{id}',
        method: 'GET',
        operationPath: '/api/v1/stories/{id}',
        run: () => apiCall('GET', '/api/v1/stories/{id}', `/stories/${ctx.story.id}`)
      },
      {
        name: 'PUT /api/v1/stories/{id}',
        method: 'PUT',
        operationPath: '/api/v1/stories/{id}',
        run: () => apiCall('PUT', '/api/v1/stories/{id}', `/stories/${ctx.story.id}`, {
          title: uniqueName('Contract Updated Story'),
          text: 'Updated contract story body.',
          status: 'active'
        })
      },
      {
        name: 'DELETE /api/v1/stories/{id}',
        method: 'DELETE',
        operationPath: '/api/v1/stories/{id}',
        run: async () => {
          const story = await global.helpers.createStory(global.resources, storyBody('Contract Delete Story'), [ctx.station.id]);
          expect(story).not.toBeNull();
          return apiCall('DELETE', '/api/v1/stories/{id}', `/stories/${story.id}`);
        }
      },
      {
        name: 'PATCH /api/v1/stories/{id}',
        method: 'PATCH',
        operationPath: '/api/v1/stories/{id}',
        run: () => apiCall('PATCH', '/api/v1/stories/{id}', `/stories/${ctx.story.id}`, { status: 'active' })
      },
      {
        name: 'GET /api/v1/stories/{id}/bulletins',
        method: 'GET',
        operationPath: '/api/v1/stories/{id}/bulletins',
        run: async () => {
          const response = await apiCall(
            'GET',
            '/api/v1/stories/{id}/bulletins',
            `/stories/${ctx.story.id}/bulletins?fields=id,filename,created_at`
          );
          expectSparseListFields(response, ['id', 'filename', 'created_at']);
          return response;
        }
      },
      {
        name: 'GET /api/v1/users',
        method: 'GET',
        operationPath: '/api/v1/users',
        run: async () => {
          const response = await apiCall('GET', '/api/v1/users', '/users?fields=id,username,role');
          expectSparseListFields(response, ['id', 'username', 'role']);
          return response;
        }
      },
      {
        name: 'POST /api/v1/users',
        method: 'POST',
        operationPath: '/api/v1/users',
        run: async () => {
          const response = await apiCall('POST', '/api/v1/users', '/users', userBody('created'));
          global.resources.track('users', response.data.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/users/{id}',
        method: 'GET',
        operationPath: '/api/v1/users/{id}',
        run: () => apiCall('GET', '/api/v1/users/{id}', `/users/${ctx.user.id}`)
      },
      {
        name: 'PUT /api/v1/users/{id}',
        method: 'PUT',
        operationPath: '/api/v1/users/{id}',
        run: () => apiCall('PUT', '/api/v1/users/{id}', `/users/${ctx.user.id}`, {
          full_name: 'Contract Updated User',
          role: 'editor'
        })
      },
      {
        name: 'DELETE /api/v1/users/{id}',
        method: 'DELETE',
        operationPath: '/api/v1/users/{id}',
        run: async () => {
          const createResponse = await global.api.apiCall('POST', '/users', userBody('delete'));
          expect(createResponse.status).toBe(201);
          const response = await apiCall('DELETE', '/api/v1/users/{id}', `/users/${createResponse.data.id}`);
          return response;
        }
      },
      {
        name: 'PATCH /api/v1/users/{id}',
        method: 'PATCH',
        operationPath: '/api/v1/users/{id}',
        run: () => apiCall('PATCH', '/api/v1/users/{id}', `/users/${ctx.user.id}`, { action: 'suspend' })
      },
      {
        name: 'GET /api/v1/bulletins',
        method: 'GET',
        operationPath: '/api/v1/bulletins',
        run: () => apiCall('GET', '/api/v1/bulletins', '/bulletins?filter[file_purged_at][null]=true')
      },
      {
        name: 'GET /api/v1/bulletins/{id}',
        method: 'GET',
        operationPath: '/api/v1/bulletins/{id}',
        run: () => apiCall('GET', '/api/v1/bulletins/{id}', `/bulletins/${ctx.bulletin.id}`)
      },
      {
        name: 'GET /api/v1/stations/{id}/bulletins',
        method: 'GET',
        operationPath: '/api/v1/stations/{id}/bulletins',
        run: () => apiCall('GET', '/api/v1/stations/{id}/bulletins', `/stations/${ctx.station.id}/bulletins`)
      },
      // This asserts the setup bulletin is still latest before the POST scenario below creates a newer one.
      {
        name: 'GET /api/v1/stations/{id}/bulletins latest',
        method: 'GET',
        operationPath: '/api/v1/stations/{id}/bulletins',
        run: async () => {
          const response = await apiCall(
            'GET',
            '/api/v1/stations/{id}/bulletins',
            `/stations/${ctx.station.id}/bulletins?latest=true`
          );
          expect(response.data).not.toHaveProperty('data');
          expect(response.data.id).toBe(ctx.bulletin.id);
          return response;
        }
      },
      // Keep this after the latest scenario: generating here creates a newer bulletin for ctx.station.
      {
        name: 'POST /api/v1/stations/{id}/bulletins',
        method: 'POST',
        operationPath: '/api/v1/stations/{id}/bulletins',
        run: () => apiCall('POST', '/api/v1/stations/{id}/bulletins', `/stations/${ctx.station.id}/bulletins`, {})
      },
      {
        name: 'GET /api/v1/bulletins/{id}/audio',
        method: 'GET',
        operationPath: '/api/v1/bulletins/{id}/audio',
        run: () => rawCall(
          'GET',
          '/api/v1/bulletins/{id}/audio',
          `${global.api.apiUrl}/bulletins/${ctx.bulletin.id}/audio`,
          { responseType: 'arraybuffer' }
        )
      },
      {
        name: 'GET /api/v1/bulletins/{id}/stories',
        method: 'GET',
        operationPath: '/api/v1/bulletins/{id}/stories',
        run: () => apiCall('GET', '/api/v1/bulletins/{id}/stories', `/bulletins/${ctx.bulletin.id}/stories`)
      },
      {
        name: 'GET /api/v1/station-voices',
        method: 'GET',
        operationPath: '/api/v1/station-voices',
        run: async () => {
          const response = await apiCall(
            'GET',
            '/api/v1/station-voices',
            '/station-voices?fields=id,station_name,voice_name,mix_point'
          );
          expectSparseListFields(response, ['id', 'station_name', 'voice_name', 'mix_point']);
          return response;
        }
      },
      {
        name: 'POST /api/v1/station-voices',
        method: 'POST',
        operationPath: '/api/v1/station-voices',
        run: async () => {
          const station = await global.helpers.createStation(global.resources, 'Contract SV Post Station');
          const voice = await global.helpers.createVoice(global.resources, 'Contract SV Post Voice');
          expect(station).not.toBeNull();
          expect(voice).not.toBeNull();

          const response = await apiCall('POST', '/api/v1/station-voices', '/station-voices', {
            station_id: station.id,
            voice_id: voice.id,
            mix_point: 4.5
          });
          global.resources.track('stationVoices', response.data.id);
          return response;
        }
      },
      {
        name: 'GET /api/v1/station-voices/{id}/audio',
        method: 'GET',
        operationPath: '/api/v1/station-voices/{id}/audio',
        run: () => rawCall(
          'GET',
          '/api/v1/station-voices/{id}/audio',
          `${global.api.apiUrl}/station-voices/${ctx.stationVoice.id}/audio`,
          { responseType: 'arraybuffer' }
        )
      },
      {
        name: 'POST /api/v1/station-voices/{id}/audio',
        method: 'POST',
        operationPath: '/api/v1/station-voices/{id}/audio',
        run: () => uploadCall(
          '/api/v1/station-voices/{id}/audio',
          `/station-voices/${ctx.stationVoice.id}/audio`,
          'jingle',
          { jingle: 'contract.wav' }
        )
      },
      {
        name: 'GET /api/v1/station-voices/{id}',
        method: 'GET',
        operationPath: '/api/v1/station-voices/{id}',
        run: () => apiCall('GET', '/api/v1/station-voices/{id}', `/station-voices/${ctx.stationVoice.id}`)
      },
      {
        name: 'PUT /api/v1/station-voices/{id}',
        method: 'PUT',
        operationPath: '/api/v1/station-voices/{id}',
        run: () => apiCall('PUT', '/api/v1/station-voices/{id}', `/station-voices/${ctx.stationVoice.id}`, { mix_point: 2.25 })
      },
      {
        name: 'DELETE /api/v1/station-voices/{id}',
        method: 'DELETE',
        operationPath: '/api/v1/station-voices/{id}',
        run: async () => {
          const station = await global.helpers.createStation(global.resources, 'Contract SV Delete Station');
          const voice = await global.helpers.createVoice(global.resources, 'Contract SV Delete Voice');
          expect(station).not.toBeNull();
          expect(voice).not.toBeNull();

          const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id, 1.5);
          expect(stationVoice).not.toBeNull();

          const response = await apiCall('DELETE', '/api/v1/station-voices/{id}', `/station-voices/${stationVoice.id}`);
          global.resources.untrack('stationVoices', stationVoice.id);
          return response;
        }
      }
    ];
  }

  async function apiCall(method, operationPath, endpoint, body = undefined, options = {}) {
    if (body !== undefined) {
      validator.validateRequest({ method, operationPath, body });
    }

    const response = await global.api.apiCall(method, endpoint, body, options);
    validator.validateResponse({ method, operationPath, response });
    return response;
  }

  async function rawCall(method, operationPath, url, options = {}) {
    const response = await global.api.http({
      method: method.toLowerCase(),
      url,
      validateStatus: () => true,
      ...options
    });

    const normalized = {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
    validator.validateResponse({ method, operationPath, response: normalized });
    return normalized;
  }

  async function uploadCall(operationPath, endpoint, fileFieldName, requestBody) {
    validator.validateRequest({
      method: 'POST',
      operationPath,
      body: requestBody,
      mediaType: 'multipart/form-data'
    });

    const audioPath = createWavFixture();
    try {
      const response = await global.api.uploadFile(endpoint, {}, audioPath, fileFieldName);
      validator.validateResponse({ method: 'POST', operationPath, response });
      return response;
    } finally {
      cleanupFile(audioPath);
    }
  }

  function expectSparseListFields(response, fields) {
    const rows = response.data?.data || [];
    expect(rows.length).toBeGreaterThan(0);

    const expected = [...fields].sort();
    for (const row of rows) {
      expect(Object.keys(row).sort()).toEqual(expected);
    }
  }
});

async function createContractContext() {
  const station = await global.helpers.createStation(global.resources, 'Contract Station');
  const voice = await global.helpers.createVoice(global.resources, 'Contract Voice');
  expect(station).not.toBeNull();
  expect(voice).not.toBeNull();

  const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id, 3.0);
  expect(stationVoice).not.toBeNull();
  await uploadFixture(`/station-voices/${stationVoice.id}/audio`, 'jingle');

  const story = await global.helpers.createStory(global.resources, storyBody('Contract Story', voice.id), [station.id]);
  expect(story).not.toBeNull();
  await uploadFixture(`/stories/${story.id}/audio`, 'audio');
  expect(await global.helpers.waitForStoryAudio(story.id)).toBe(true);

  const bulletinResponse = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
  expect(bulletinResponse.status).toBe(200);
  expect(bulletinResponse.data?.id).toBeDefined();

  const userResponse = await global.api.apiCall('POST', '/users', userBody('base'));
  expect(userResponse.status).toBe(201);
  global.resources.track('users', userResponse.data.id);

  return {
    station,
    voice,
    stationVoice,
    story,
    bulletin: bulletinResponse.data,
    user: { id: userResponse.data.id }
  };
}

async function uploadFixture(endpoint, fileFieldName) {
  const audioPath = createWavFixture();
  try {
    const response = await global.api.uploadFile(endpoint, {}, audioPath, fileFieldName);
    expect(response.status).toBe(201);
    return response;
  } finally {
    cleanupFile(audioPath);
  }
}

function stationBody(prefix) {
  return {
    name: uniqueName(prefix),
    max_stories_per_block: 4,
    pause_seconds: 1.5
  };
}

function voiceBody(prefix) {
  return {
    name: uniqueName(prefix)
  };
}

function storyBody(prefix, voiceId = null) {
  const now = new Date();
  const startDate = now.toISOString().split('T')[0];
  const endDate = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

  return {
    title: uniqueName(prefix),
    text: 'Contract validation story content.',
    voice_id: voiceId,
    status: 'active',
    start_date: startDate,
    end_date: endDate,
    weekdays: 127,
    is_breaking: false
  };
}

function userBody(suffix) {
  return {
    username: `contract${suffix}${Date.now()}${process.pid}`.replace(/[^a-zA-Z0-9]/g, ''),
    full_name: `Contract ${suffix} User`,
    password: 'ContractPass123!',
    role: 'viewer'
  };
}

function uniqueName(prefix) {
  return `${prefix} ${Date.now()} ${process.pid} ${Math.random().toString(36).slice(2, 8)}`;
}

function createWavFixture() {
  const filePath = path.join(os.tmpdir(), `babbel-contract-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.wav`);
  fs.writeFileSync(filePath, wavBuffer());
  return filePath;
}

function cleanupFile(filePath) {
  try {
    fs.unlinkSync(filePath);
  } catch {
    // Best-effort cleanup for temporary test fixtures.
  }
}

function wavBuffer() {
  const sampleRate = 44100;
  const durationSeconds = 1;
  const channelCount = 1;
  const bytesPerSample = 2;
  const sampleCount = sampleRate * durationSeconds;
  const dataSize = sampleCount * channelCount * bytesPerSample;
  const buffer = Buffer.alloc(44 + dataSize);

  buffer.write('RIFF', 0);
  buffer.writeUInt32LE(36 + dataSize, 4);
  buffer.write('WAVE', 8);
  buffer.write('fmt ', 12);
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(channelCount, 22);
  buffer.writeUInt32LE(sampleRate, 24);
  buffer.writeUInt32LE(sampleRate * channelCount * bytesPerSample, 28);
  buffer.writeUInt16LE(channelCount * bytesPerSample, 32);
  buffer.writeUInt16LE(8 * bytesPerSample, 34);
  buffer.write('data', 36);
  buffer.writeUInt32LE(dataSize, 40);

  for (let i = 0; i < sampleCount; i++) {
    const sample = Math.round(Math.sin((2 * Math.PI * 440 * i) / sampleRate) * 32767 * 0.25);
    buffer.writeInt16LE(sample, 44 + i * bytesPerSample);
  }

  return buffer;
}
