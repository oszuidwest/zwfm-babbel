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
    const error = new Error('ffmpeg failed');
    error.stderr = Buffer.from('invalid sine filter');
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'ffmpeg' && args[0] === '-version') {
        return '';
      }
      throw error;
    });

    const helpers = new TestHelpers({});

    expect(() => helpers.createTestAudioFile('/tmp/out.wav', 1, 440)).toThrow(expect.objectContaining({
      message: expect.stringContaining('invalid sine filter'), cause: error
    }));
  });

  test('when ffmpeg succeeds without creating output, then throws with its cause', () => {
    execFileSync.mockReturnValue('');
    jest.spyOn(fsSync, 'existsSync').mockReturnValue(false);

    const helpers = new TestHelpers({});

    expect(() => helpers.createTestAudioFile('/tmp/out.wav', 1, 440)).toThrow(expect.objectContaining({
      message: expect.stringContaining('output file was not created'), cause: expect.any(Error)
    }));
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

  test('when ffmpeg is missing, then audio creation throws with its cause', () => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const cause = new Error('spawn ffmpeg ENOENT');
    execFileSync.mockImplementation(() => { throw cause; });
    const helpers = new TestHelpers({});
    expect(() => helpers.createTestAudioFile('/tmp/out.wav')).toThrow(expect.objectContaining({
      message: expect.stringContaining('ENOENT'), cause
    }));
  });

  test('when audio creation succeeds, then returns the file path', () => {
    execFileSync.mockReturnValue('');
    jest.spyOn(fsSync, 'existsSync').mockReturnValue(true);
    expect(new TestHelpers({}).createTestAudioFile('/tmp/out.wav')).toBe('/tmp/out.wav');
  });

  test('story audio fixture resolves only after the upload completes', async () => {
    let finishUpload;
    const api = { uploadFile: jest.fn().mockReturnValue(new Promise(resolve => { finishUpload = resolve; })) };
    const helpers = new TestHelpers(api);
    jest.spyOn(helpers, 'createTestAudioFile').mockReturnValue('/tmp/out.wav');
    jest.spyOn(helpers, 'createStory').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, 'cleanupTempFile').mockImplementation(() => {});
    let finished = false;
    const fixture = helpers.createStoryWithAudio({ track: jest.fn() }, {}).then(story => { finished = true; return story; });
    await Promise.resolve();
    expect(api.uploadFile).toHaveBeenCalledWith('/stories/40/audio', {}, expect.any(String), 'audio');
    expect(finished).toBe(false);
    finishUpload({ status: 201, data: { message: 'Audio uploaded successfully' } });
    await expect(fixture).resolves.toEqual({ id: 40 });
    expect(helpers.cleanupTempFile).toHaveBeenCalledTimes(1);
  });

  test('when bulletin job reaches a terminal state, then returns the API response', async () => {
    const queued = { status: 200, data: { status: 'queued' } };
    const failed = { status: 200, data: { status: 'failed', error_code: 'bulletin.no_stories' } };
    const api = { apiCall: jest.fn().mockResolvedValueOnce(queued).mockResolvedValueOnce(failed) };
    const helpers = new TestHelpers(api);
    jest.spyOn(helpers, 'sleep').mockResolvedValue();

    await expect(helpers.waitForBulletinJob(42)).resolves.toBe(failed);
    expect(api.apiCall).toHaveBeenCalledTimes(2);
    expect(helpers.sleep).toHaveBeenCalledTimes(1);
  });

  test('when bulletin job polling returns an HTTP error, then throws immediately', async () => {
    const api = { apiCall: jest.fn().mockResolvedValue({ status: 500, data: { status: 500 } }) };
    const helpers = new TestHelpers(api);
    jest.spyOn(helpers, 'sleep').mockResolvedValue();

    await expect(helpers.waitForBulletinJob(42)).rejects.toThrow(
      'Fixture GET /bulletin-jobs/42 failed: HTTP 500; body {"status":500}'
    );
    expect(api.apiCall).toHaveBeenCalledTimes(1);
    expect(helpers.sleep).not.toHaveBeenCalled();
  });

  test('when bulletin job fails, then generateBulletin throws', async () => {
    const accepted = { status: 202, data: { id: 7 } };
    const failed = { status: 200, data: { status: 'failed', error_code: 'bulletin.no_stories' } };
    const api = { apiCall: jest.fn().mockResolvedValueOnce(accepted).mockResolvedValueOnce(failed) };
    const helpers = new TestHelpers(api);

    await expect(helpers.generateBulletin(3)).rejects.toThrow(
      'Bulletin job 7 failed: bulletin.no_stories'
    );
  });

  test.each([
    ['createStation', ['Station'], '/stations'],
    ['createVoice', ['Voice'], '/voices'],
    ['createStory', [{ title: 'Story' }], '/stories'],
    ['createStationVoice', [1, 2], '/station-voices']
  ])('%s failure includes method, path, status and problem body', async (method, args, endpoint) => {
    const api = { apiCall: jest.fn().mockResolvedValue({ status: 503, data: { detail: 'database unavailable' } }) };
    const helpers = new TestHelpers(api);
    const resources = { track: jest.fn() };
    await expect(helpers[method](resources, ...args)).rejects.toThrow(
      `Fixture POST ${endpoint} failed: HTTP 503; body {"detail":"database unavailable"}`
    );
    expect(resources.track).not.toHaveBeenCalled();
  });

  test('a successful status without a fixture ID still includes the broken body', async () => {
    const helpers = new TestHelpers({ apiCall: jest.fn().mockResolvedValue({ status: 201, data: { name: 'missing ID' } }) });
    await expect(helpers.createStation({ track: jest.fn() }, 'Station')).rejects.toThrow('HTTP 201; body {"name":"missing ID"}');
  });

  test.each(['createStoryWithAudio', 'createStationVoiceWithJingle'])('%s reports missing FFmpeg explicitly', async method => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    execFileSync.mockImplementation(() => { throw new Error('spawn ffmpeg ENOENT'); });
    const helpers = new TestHelpers({});
    const args = method === 'createStoryWithAudio' ? [{}] : [1, 2];
    await expect(helpers[method]({ track: jest.fn() }, ...args)).rejects.toThrow(/FFmpeg.*not available.*ENOENT/);
  });

  test('story audio upload failure retains the response and cleans temporary audio', async () => {
    const helpers = new TestHelpers({ uploadFile: jest.fn().mockResolvedValue({ status: 422, data: { errors: [{ code: 'undecodable_audio' }] } }) });
    jest.spyOn(helpers, 'createTestAudioFile').mockReturnValue('/tmp/out.wav');
    jest.spyOn(helpers, 'createStory').mockResolvedValue({ id: 40 });
    jest.spyOn(helpers, 'cleanupTempFile').mockImplementation(() => {});
    await expect(helpers.createStoryWithAudio({ track: jest.fn() }, {})).rejects.toThrow('POST /stories/40/audio failed: HTTP 422; body {"errors":[{"code":"undecodable_audio"}]}');
    expect(helpers.cleanupTempFile).toHaveBeenCalledTimes(1);
  });

  test('when station voice IDs are unsafe, then API is not called', async () => {
    const api = { apiCall: jest.fn() };
    const helpers = new TestHelpers(api);

    await expect(helpers.createStationVoice({ track: jest.fn() }, '1 OR 1=1', 2)).rejects.toThrow(/station ID/);
    expect(api.apiCall).not.toHaveBeenCalled();
  });

  test('when story voice ID is unsafe, then API is not called', async () => {
    const api = { apiCall: jest.fn() };
    const helpers = new TestHelpers(api);

    await expect(
      helpers.createStory({ track: jest.fn() }, { title: 'x', voice_id: '1 OR 1=1' })
    ).rejects.toThrow(/voice_id/);
    expect(api.apiCall).not.toHaveBeenCalled();
  });

  test('when creating stories with audio, then applies shared voice defaults', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStoryWithAudio')
      .mockResolvedValueOnce({ id: 1 })
      .mockResolvedValueOnce({ id: 2 });

    const stories = await helpers.createStoriesWithAudio(
      resourceManager,
      20,
      [
        { title: 'Breaking', text: 'Breaking story', is_breaking: true },
        { title: 'Regular', text: 'Regular story', is_breaking: false }
      ]
    );

    expect(helpers.createStoryWithAudio).toHaveBeenNthCalledWith(
      1,
      resourceManager,
      expect.objectContaining({
        title: 'Breaking',
        text: 'Breaking story',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      })
    );
    expect(helpers.createStoryWithAudio).toHaveBeenNthCalledWith(
      2,
      resourceManager,
      expect.objectContaining({
        title: 'Regular',
        text: 'Regular story',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: false
      })
    );
    expect(stories).toEqual([{ id: 1 }, { id: 2 }]);
  });

  test('when jingle upload fails, then station voice with jingle reports status and body', async () => {
    const api = {
      uploadFile: jest.fn().mockResolvedValue({ status: 500, data: { detail: 'read-only volume' } })
    };
    const helpers = new TestHelpers(api);

    jest.spyOn(helpers, 'createTestAudioFile').mockReturnValue('/tmp/out.wav');
    jest.spyOn(helpers, 'createStationVoice').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'cleanupTempFile').mockImplementation(() => {});

    await expect(helpers.createStationVoiceWithJingle({ track: jest.fn() }, 10, 20, 2.5)).rejects.toThrow('POST /station-voices/30/audio failed: HTTP 500; body {"detail":"read-only volume"}');
    expect(api.uploadFile).toHaveBeenCalledWith('/station-voices/30/audio', {}, expect.any(String), 'jingle');
    expect(helpers.cleanupTempFile).toHaveBeenCalledTimes(1);
  });

  test('when creating broadcast fixture, then dependencies and uploaded audio are created', async () => {
    const helpers = new TestHelpers({});
    const resourceManager = { track: jest.fn() };

    jest.spyOn(helpers, 'createStation').mockResolvedValue({ id: 10, name: 'Station' });
    jest.spyOn(helpers, 'createVoice').mockResolvedValue({ id: 20, name: 'Voice' });
    jest.spyOn(helpers, 'createStationVoiceWithJingle').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'createStoryWithAudio').mockResolvedValue({ id: 40 });
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
    expect(helpers.createStoryWithAudio).toHaveBeenCalledWith(
      resourceManager,
      expect.objectContaining({
        title: 'Unique Story',
        text: 'Story body',
        voice_id: 20,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      })
    );
    expect(fixture).toEqual({
      station: { id: 10, name: 'Station' },
      voice: { id: 20, name: 'Voice' },
      stationVoice: { id: 30 },
      story: { id: 40 }
    });
  });

  test.each([
    ['station', 'createStation'],
    ['voice', 'createVoice'],
    ['station voice', 'createStationVoiceWithJingle'],
    ['story audio', 'createStoryWithAudio']
  ])('when creating broadcast fixture fails at %s, then preserves its cause', async (_label, methodName) => {
    const helpers = new TestHelpers({});

    jest.spyOn(helpers, 'createStation').mockResolvedValue({ id: 10, name: 'Station' });
    jest.spyOn(helpers, 'createVoice').mockResolvedValue({ id: 20, name: 'Voice' });
    jest.spyOn(helpers, 'createStationVoiceWithJingle').mockResolvedValue({ id: 30 });
    jest.spyOn(helpers, 'createStoryWithAudio').mockResolvedValue({ id: 40 });
    const cause = new Error(`${_label} setup failed`);
    jest.spyOn(helpers, methodName).mockRejectedValue(cause);

    await expect(helpers.createBroadcastFixture({ track: jest.fn() })).rejects.toBe(cause);
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
