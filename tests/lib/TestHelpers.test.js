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

  test('when creating broadcast fixture, then dependencies are created and audio is awaited', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStation').mockResolvedValue({ id: 10, name: 'Station' });
    jest.spyOn(helpers, 'createVoice').mockResolvedValue({ id: 20, name: 'Voice' });
    jest.spyOn(helpers, 'createStationVoiceWithJingle').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'createStoryWithReadyAudio').mockResolvedValue({ id: 40 });
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
    expect(helpers.createStoryWithReadyAudio).toHaveBeenCalledWith(
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

});
