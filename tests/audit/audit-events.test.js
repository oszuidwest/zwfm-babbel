const { createUser, switchToUser, restoreAdmin } = require('../lib/RoleHelpers');

describe('Audit events', () => {
  let admin;
  let station;
  let originalSettings;
  let originalPronunciations;
  const roles = {};
  const password = 'AuditPass123!';

  beforeAll(async () => {
    await restoreAdmin();
    admin = await global.api.getCurrentSession();
    expect(admin).not.toBeNull();
    station = await global.helpers.createStation(global.resources, 'Audit station');
    expect(station).not.toBeNull();

    const settings = await global.api.apiCall('GET', '/settings/tts');
    expect(settings.status).toBe(200);
    originalSettings = settings.data;
    const pronunciations = await global.api.apiCall('GET', '/settings/tts/pronunciations');
    expect(pronunciations.status).toBe(200);
    originalPronunciations = pronunciations.data.rules;

    for (const role of ['viewer', 'editor']) {
      const username = `audit${role}${Date.now()}`;
      expect(await createUser(username, `Audit ${role}`, password, role)).not.toBeNull();
      roles[role] = username;
    }
  });

  afterEach(async () => {
    await restoreAdmin();
  });

  afterAll(async () => {
    if (originalSettings) {
      const response = await global.api.apiCall('PATCH', '/settings/tts', {
        tts_style_prefix: originalSettings.tts_style_prefix
      });
      expect(response.status).toBe(200);
    }
    if (originalPronunciations) {
      const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', {
        rules: originalPronunciations
      });
      expect(response.status).toBe(200);
    }
  });

  test('when admin changes a story, then history has attributed old/new values newest first', async () => {
    const story = await createStory('Original audit title');
    const path = `/stories/${story.id}`;
    expect((await global.api.apiCall('PUT', path, { title: 'Edited audit title' })).status).toBe(200);
    expect((await global.api.apiCall('PATCH', path, { status: 'active' })).status).toBe(200);
    expect((await global.api.apiCall('DELETE', path)).status).toBe(204);
    expect((await global.api.apiCall('PATCH', path, { deleted_at: '' })).status).toBe(200);

    const history = await listEvents(`filter[entity_type]=story&filter[entity_id]=${story.id}`);
    expect(history.total).toBe(5);
    expect(history.data.map(event => event.action)).toEqual(['restore', 'delete', 'update', 'update', 'create']);
    expect(history.data.map(event => event.id)).toEqual(history.data.map(event => event.id).sort((a, b) => b - a));
    for (const event of history.data) {
      expect(event).toEqual(expect.objectContaining({
        actor_type: 'user', user_id: admin.id, username: admin.username, full_name: admin.full_name
      }));
      expect(event.occurred_at).toEqual(expect.any(String));
    }
    expect(history.data[4].changes).toEqual(expect.objectContaining({
      title: { old: null, new: 'Original audit title' },
      status: { old: null, new: 'draft' },
      audio_file: { old: null, new: '' }
    }));
    expect(history.data[3].changes).toEqual({ title: { old: 'Original audit title', new: 'Edited audit title' } });
    expect(history.data[2].changes).toEqual({ status: { old: 'draft', new: 'active' } });
    expect(history.data[1].changes.deleted_at).toEqual({ old: null, new: expect.any(String) });
    expect(history.data[0].changes.deleted_at).toEqual({ old: history.data[1].changes.deleted_at.new, new: null });
  });

  test('when admin patches TTS settings twice identically, then only one event is written', async () => {
    const before = await global.api.apiCall('GET', '/settings/tts');
    expect(before.status).toBe(200);
    const filter = `filter[entity_type]=tts_settings&filter[entity_id]=1&filter[id][gt]=${await latestEventID('tts_settings')}`;
    const body = { tts_style_prefix: global.helpers.uniqueName('Audit prefix') };
    expect((await global.api.apiCall('PATCH', '/settings/tts', body)).status).toBe(200);
    const first = await listEvents(filter);
    expect(first.total).toBe(1);
    expect(first.data[0]).toEqual(expect.objectContaining({ action: 'update', user_id: admin.id }));
    expect(first.data[0].changes).toEqual({
      tts_style_prefix: { old: before.data.tts_style_prefix, new: body.tts_style_prefix }
    });

    expect((await global.api.apiCall('PATCH', '/settings/tts', body)).status).toBe(200);
    const repeated = await listEvents(filter);
    expect(repeated.total).toBe(1);
    expect(repeated.data.map(event => event.id)).toEqual([first.data[0].id]);
  });

  test('when admin replaces pronunciation rules twice identically, then only one event is written', async () => {
    const filter = `filter[entity_type]=pronunciation_rules&filter[entity_id]=1&filter[id][gt]=${await latestEventID('pronunciation_rules')}`;
    const rule = {
      string_to_replace: global.helpers.uniqueName('Audit term'),
      ipa: 'test', case_sensitive: true, word_boundaries: true
    };
    const body = { rules: [rule] };
    expect((await global.api.apiCall('PUT', '/settings/tts/pronunciations', body)).status).toBe(200);
    const first = await listEvents(filter);
    expect(first.total).toBe(1);
    expect(first.data[0]).toEqual(expect.objectContaining({ action: 'update', user_id: admin.id }));
    expect(first.data[0].changes[rule.string_to_replace]).toEqual({
      old: null, new: { ipa: 'test', case_sensitive: true, word_boundaries: true }
    });

    expect((await global.api.apiCall('PUT', '/settings/tts/pronunciations', body)).status).toBe(200);
    const repeated = await listEvents(filter);
    expect(repeated.total).toBe(1);
    expect(repeated.data.map(event => event.id)).toEqual([first.data[0].id]);
  });

  test('when viewer reads and filters story and settings history, then actor names are null but user IDs remain', async () => {
    const story = await createStory('Viewer audit access');
    const storyHistory = await listEvents(`filter[entity_type]=story&filter[entity_id]=${story.id}`);
    expect((await global.api.apiCall('PATCH', '/settings/tts', {
      tts_style_prefix: global.helpers.uniqueName('Viewer audit prefix')
    })).status).toBe(200);
    expect((await global.api.apiCall('PUT', '/settings/tts/pronunciations', {
      rules: [{ string_to_replace: global.helpers.uniqueName('Viewer audit term'), ipa: 'test' }]
    })).status).toBe(200);
    const storyID = storyHistory.data[0].id;
    const settingsID = await latestEventID('tts_settings');
    const pronunciationID = await latestEventID('pronunciation_rules');
    const fixtureFilter = `filter[id][in]=${storyID},${settingsID},${pronunciationID}`;

    expect(await switchToUser(roles.viewer, password)).toBe(true);
    const session = await global.api.getCurrentSession();
    expect(session.permissions.users || []).not.toContain('read');
    for (const [filter, ids] of [
      ['', [storyID, settingsID, pronunciationID]],
      ['&filter[entity_type]=pronunciation_rules', [pronunciationID]],
      ['&filter[entity_type][in]=story,pronunciation_rules', [storyID, pronunciationID]]
    ]) {
      const history = await listEvents(fixtureFilter + filter);
      expect(history.total).toBe(ids.length);
      expect(history.data.map(event => event.id).sort((a, b) => a - b)).toEqual(ids.sort((a, b) => a - b));
      for (const event of history.data) {
        expect(event).toEqual(expect.objectContaining({ user_id: admin.id, username: null, full_name: null }));
      }
    }
  });

  test('when editor reads story history, then actor names are present', async () => {
    const story = await createStory('Editor audit access');
    expect(await switchToUser(roles.editor, password)).toBe(true);
    const session = await global.api.getCurrentSession();
    expect(session.permissions.users).toContain('read');
    const history = await listEvents(`filter[entity_type]=story&filter[entity_id]=${story.id}`);
    expect(history.total).toBe(1);
    expect(history.data[0]).toEqual(expect.objectContaining({
      user_id: admin.id, username: admin.username, full_name: admin.full_name
    }));
  });

  async function createStory(title) {
    const story = await global.helpers.createStory(global.resources, { title, status: 'draft' }, [station.id]);
    expect(story).not.toBeNull();
    return story;
  }

  async function listEvents(query) {
    const response = await global.api.apiCall('GET', `/audit-events?${query}`);
    expect(response.status).toBe(200);
    return response.data;
  }

  async function latestEventID(entity) {
    const history = await listEvents(`filter[entity_type]=${entity}&filter[entity_id]=1&limit=1`);
    return history.data[0]?.id || 0;
  }
});
