jest.mock('child_process', () => ({
  execFileSync: jest.fn()
}));

const { execFileSync } = require('child_process');
const fsSync = require('fs');
const TestHelpers = require('./TestHelpers');

describe('TestHelpers', () => {
  beforeEach(() => {
    execFileSync.mockReset();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('when ffmpeg is unavailable, then root cause is logged', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const error = new Error('spawn ffmpeg ENOENT');
    error.code = 'ENOENT';
    execFileSync.mockImplementation(() => {
      throw error;
    });

    const helpers = new TestHelpers({});

    expect(helpers.isFFmpegAvailable()).toBe(false);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('ENOENT'));
  });

  test('when audio duration is not numeric, then ffmpeg is not invoked', () => {
    const helpers = new TestHelpers({});

    expect(() => helpers.createTestAudioFile('/tmp/out.wav', '1; rm -rf /', 440)).toThrow(/audio duration/);
    expect(execFileSync).not.toHaveBeenCalled();
  });

  test('when audio frequency is not numeric, then ffmpeg is not invoked', () => {
    const helpers = new TestHelpers({});

    expect(() => helpers.createTestAudioFile('/tmp/out.wav', 1, '440; cat /etc/passwd')).toThrow(/audio frequency/);
    expect(execFileSync).not.toHaveBeenCalled();
  });

  test('when ffmpeg generation fails, then command details are preserved', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'ffmpeg' && args[0] === '-version') {
        return '';
      }
      const error = new Error('ffmpeg failed');
      error.stderr = Buffer.from('invalid sine filter');
      throw error;
    });

    const helpers = new TestHelpers({});

    expect(helpers.createTestAudioFile('/tmp/out.wav', 1, 440)).toBe(false);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('invalid sine filter'));
  });

  test('when ffmpeg succeeds without creating output, then returns false with warning', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    execFileSync.mockReturnValue('');
    jest.spyOn(fsSync, 'existsSync').mockReturnValue(false);

    const helpers = new TestHelpers({});

    expect(helpers.createTestAudioFile('/tmp/out.wav', 1, 440)).toBe(false);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('output file was not created'));
  });

  test('when checking ffmpeg repeatedly, then result is memoized', () => {
    execFileSync.mockReturnValue('');

    const helpers = new TestHelpers({});

    expect(helpers.isFFmpegAvailable()).toBe(true);
    expect(helpers.isFFmpegAvailable()).toBe(true);
    expect(execFileSync).toHaveBeenCalledTimes(1);
  });

  test('when cleanup fails for an existing temp file, then warning is logged', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const error = new Error('permission denied');
    error.code = 'EACCES';
    jest.spyOn(fsSync, 'unlinkSync').mockImplementation(() => {
      throw error;
    });

    const helpers = new TestHelpers({});
    helpers.cleanupTempFile('/tmp/test.wav');

    expect(warn).toHaveBeenCalledWith(expect.stringContaining('permission denied'));
  });

  test('when waiting for story audio times out, then returns false', async () => {
    const api = {
      apiCall: jest.fn().mockResolvedValue({ status: 200, data: {} })
    };
    const helpers = new TestHelpers(api);

    jest.spyOn(Date, 'now')
      .mockReturnValueOnce(0)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce(4);
    jest.spyOn(helpers, 'sleep').mockResolvedValue();

    await expect(helpers.waitForStoryAudio(40, 3, 1)).resolves.toBe(false);
    expect(api.apiCall).toHaveBeenCalledWith('GET', '/stories/40');
  });

  test('when station voice IDs are unsafe, then API is not called', async () => {
    const api = { apiCall: jest.fn() };
    const helpers = new TestHelpers(api);

    await expect(helpers.createStationVoice({ track: jest.fn() }, '1 OR 1=1', 2)).rejects.toThrow(/station ID/);
    expect(api.apiCall).not.toHaveBeenCalled();
  });

  test('when story target station ID is unsafe, then API is not called', async () => {
    const api = { apiCall: jest.fn() };
    const helpers = new TestHelpers(api);

    await expect(
      helpers.createStory({ track: jest.fn() }, { title: 'x', voice_id: 1 }, ['2; DROP TABLE stations'])
    ).rejects.toThrow(/target station ID/);
    expect(api.apiCall).not.toHaveBeenCalled();
  });

  test('when creating story with ready audio, then waits until audio is exposed', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStoryWithAudio').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, 'waitForStoryAudio').mockResolvedValue(true);

    const story = await helpers.createStoryWithReadyAudio(
      resourceManager,
      { title: 'Story with audio' },
      [10]
    );

    expect(helpers.createStoryWithAudio).toHaveBeenCalledWith(
      resourceManager,
      { title: 'Story with audio' },
      [10]
    );
    expect(helpers.waitForStoryAudio).toHaveBeenCalledWith(40);
    expect(story).toEqual({ id: 40 });
  });

  test('when creating story with ready audio times out, then returns null', async () => {
    const helpers = new TestHelpers({});

    jest.spyOn(helpers, 'createStoryWithAudio').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, 'waitForStoryAudio').mockResolvedValue(false);

    await expect(
      helpers.createStoryWithReadyAudio({ track: jest.fn() }, { title: 'Story with audio' }, [10])
    ).resolves.toBeNull();
  });

  test('when requiring story with ready audio fails, then throws', async () => {
    const helpers = new TestHelpers({});

    jest.spyOn(helpers, 'createStoryWithReadyAudio').mockResolvedValue(null);

    await expect(
      helpers.requireStoryWithReadyAudio({ track: jest.fn() }, { title: 'Required story' }, [10])
    ).rejects.toThrow(/Required story/);
  });

  test('when creating station stories with ready audio, then applies shared station and voice defaults', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStoryWithReadyAudio')
      .mockResolvedValueOnce({ id: 1 })
      .mockResolvedValueOnce({ id: 2 });

    const stories = await helpers.createStationStoriesWithReadyAudio(
      resourceManager,
      10,
      20,
      [
        { title: 'Breaking', text: 'Breaking story', is_breaking: true },
        { title: 'Regular', text: 'Regular story', is_breaking: false }
      ]
    );

    expect(helpers.createStoryWithReadyAudio).toHaveBeenNthCalledWith(
      1,
      resourceManager,
      expect.objectContaining({
        title: 'Breaking',
        text: 'Breaking story',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      }),
      [10]
    );
    expect(helpers.createStoryWithReadyAudio).toHaveBeenNthCalledWith(
      2,
      resourceManager,
      expect.objectContaining({
        title: 'Regular',
        text: 'Regular story',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: false
      }),
      [10]
    );
    expect(stories).toEqual([{ id: 1 }, { id: 2 }]);
  });

  test('when requiring station stories with ready audio fails, then throws', async () => {
    const helpers = new TestHelpers({});

    jest.spyOn(helpers, 'createStationStoriesWithReadyAudio').mockResolvedValue(null);

    await expect(
      helpers.requireStationStoriesWithReadyAudio({ track: jest.fn() }, 10, 20, [{ title: 'Missing audio' }])
    ).rejects.toThrow(/station 10 and voice 20/);
  });

  test('when jingle upload fails, then station voice with jingle returns null with warning', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const api = {
      uploadFile: jest.fn().mockResolvedValue({ status: 500 })
    };
    const helpers = new TestHelpers(api);

    jest.spyOn(helpers, 'isFFmpegAvailable').mockReturnValue(true);
    jest.spyOn(helpers, 'createTestAudioFile').mockReturnValue(true);
    jest.spyOn(helpers, 'createStationVoice').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'cleanupTempFile').mockImplementation(() => {});

    await expect(helpers.createStationVoiceWithJingle({ track: jest.fn() }, 10, 20, 2.5)).resolves.toBeNull();
    expect(api.uploadFile).toHaveBeenCalledWith('/station-voices/30/audio', {}, expect.any(String), 'jingle');
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('HTTP 500'));
  });

  test('when creating broadcast fixture, then dependencies are created and audio is awaited', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStation').mockResolvedValue({ id: 10, name: 'Station' });
    jest.spyOn(helpers, 'createVoice').mockResolvedValue({ id: 20, name: 'Voice' });
    jest.spyOn(helpers, 'createStationVoiceWithJingle').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'requireStoryWithReadyAudio').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, 'uniqueName').mockReturnValue('Unique Story');

    const fixture = await helpers.createBroadcastFixture(resourceManager, {
      stationName: 'Station',
      voiceName: 'Voice',
      storyTitle: 'Story',
      storyText: 'Story body',
      maxStories: 3,
      pauseSeconds: 1.5,
      mixPoint: 2.5,
      storyOverrides: { is_breaking: true }
    });

    expect(helpers.createStation).toHaveBeenCalledWith(resourceManager, 'Station', 3, 1.5);
    expect(helpers.createVoice).toHaveBeenCalledWith(resourceManager, 'Voice');
    expect(helpers.createStationVoiceWithJingle).toHaveBeenCalledWith(resourceManager, 10, 20, 2.5);
    expect(helpers.requireStoryWithReadyAudio).toHaveBeenCalledWith(
      resourceManager,
      expect.objectContaining({
        title: 'Unique Story',
        text: 'Story body',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      }),
      [10]
    );
    expect(fixture).toEqual({
      station: { id: 10, name: 'Station' },
      voice: { id: 20, name: 'Voice' },
      stationVoice: { id: 30 },
      story: { id: 40 }
    });
  });

  test.each([
    ['station', 'createStation', () => null, /Failed to create station fixture/],
    ['voice', 'createVoice', () => null, /Failed to create voice fixture/],
    ['station voice', 'createStationVoiceWithJingle', () => null, /Failed to create station-voice fixture/],
    ['story audio', 'requireStoryWithReadyAudio', () => Promise.reject(new Error('story setup failed')), /story setup failed/]
  ])('when creating broadcast fixture fails at %s, then throws', async (_label, methodName, resultFactory, errorPattern) => {
    const helpers = new TestHelpers({});

    jest.spyOn(helpers, 'createStation').mockResolvedValue({ id: 10, name: 'Station' });
    jest.spyOn(helpers, 'createVoice').mockResolvedValue({ id: 20, name: 'Voice' });
    jest.spyOn(helpers, 'createStationVoiceWithJingle').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'requireStoryWithReadyAudio').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, methodName).mockImplementation(resultFactory);

    await expect(helpers.createBroadcastFixture({ track: jest.fn() })).rejects.toThrow(errorPattern);
  });

  test('when public bulletin request is made, then station ID and query params are encoded', async () => {
    const api = {
      apiBase: 'http://example.test',
      http: jest.fn().mockResolvedValue({
        status: 200,
        data: Buffer.from('wav'),
        headers: { 'content-type': 'audio/wav' }
      })
    };
    const helpers = new TestHelpers(api);

    const response = await helpers.publicBulletinRequest(10, { key: 'secret key', max_age: '3600' });

    expect(api.http).toHaveBeenCalledWith(expect.objectContaining({
      method: 'get',
      url: 'http://example.test/public/stations/10/bulletin.wav?key=secret+key&max_age=3600',
      responseType: 'arraybuffer',
      validateStatus: expect.any(Function)
    }));
    expect(response).toEqual({
      status: 200,
      data: Buffer.from('wav'),
      headers: { 'content-type': 'audio/wav' },
      contentType: 'audio/wav'
    });
  });

});
