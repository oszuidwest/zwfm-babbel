describe('Soft-deleted story audio', () => {
  test('audio remains downloadable from the trash and after restoration', async () => {
    const voice = await global.helpers.createVoice(global.resources, 'Trash audio voice');
    expect(voice).not.toBeNull();
    const story = await global.helpers.requireStoryWithReadyAudio(global.resources, {
      title: 'Trash audio preview',
      voice_id: voice.id
    });
    const storyPath = `/stories/${story.id}`;
    const audioPath = `${storyPath}/audio`;
    const download = () => global.api.apiCall('GET', audioPath, null, { responseType: 'arraybuffer' });
    const before = await download();
    expect(before.status).toBe(200);
    expect(before.headers['content-type']).toContain('audio/wav');
    expect(before.data.length).toBeGreaterThan(44);

    const deleted = await global.api.apiCall('DELETE', storyPath);
    expect(deleted.status).toBe(204);
    const hidden = await global.api.apiCall('GET', storyPath);
    expect(hidden.status).toBe(404);

    const trash = await global.api.apiCall('GET', `/stories?trashed=only&filter[id]=${story.id}`);
    expect(trash.status).toBe(200);
    expect(trash.data.data).toHaveLength(1);
    expect(trash.data.data[0].id).toBe(story.id);
    expect(trash.data.data[0].audio_url).toContain(audioPath);
    const inTrash = await download();
    expect(inTrash.status).toBe(200);
    expect(Buffer.from(inTrash.data).equals(Buffer.from(before.data))).toBe(true);

    const restored = await global.api.apiCall('PATCH', storyPath, { deleted_at: '' });
    expect(restored.status).toBe(200);
    expect(restored.data.deleted_at).toBeNull();
    const after = await download();
    expect(after.status).toBe(200);
    expect(Buffer.from(after.data).equals(Buffer.from(before.data))).toBe(true);
  });
});
