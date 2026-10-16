const ResourceManager = require('./ResourceManager');

describe('ResourceManager', () => {
  test('when API cleanup is blocked by dependencies, then tracked rows are hard-deleted in dependency order', async () => {
    const api = { apiCall: jest.fn().mockResolvedValue({ status: 409 }) };
    const mysql = { execSQLScript: jest.fn() };
    const resources = new ResourceManager(api, mysql);

    resources.track('bulletins', 10);
    resources.track('stories', 9);
    resources.track('stationVoices', 11);
    resources.track('voices', 8);
    resources.track('stations', 7);
    resources.track('users', 12);

    await resources.cleanupAll();
    expect(api.apiCall).not.toHaveBeenCalledWith('DELETE', expect.stringContaining('/bulletins/'));
    expect(mysql.execSQLScript).toHaveBeenCalledTimes(1);

    const sql = mysql.execSQLScript.mock.calls[0][0];
    expect(sql).toContain('DELETE FROM bulletins WHERE id IN (10) OR station_id IN (7)');
    expect(sql).toContain('DELETE FROM stories WHERE id IN (9)');
    expect(sql.indexOf('DELETE FROM stories')).toBeLessThan(sql.indexOf('DELETE FROM voices'));
    expect(sql.indexOf('DELETE FROM station_voices')).toBeLessThan(sql.indexOf('DELETE FROM stations'));
    for (const ids of Object.values(resources.tracked)) expect(ids.size).toBe(0);
  });

  test('when database cleanup fails, then the failure remains visible', async () => {
    const api = { apiCall: jest.fn().mockResolvedValue({ status: 204 }) };
    const mysql = { execSQLScript: jest.fn(() => { throw new Error('database unavailable'); }) };
    const resources = new ResourceManager(api, mysql);
    resources.track('stations', 7);

    await expect(resources.cleanupAll()).rejects.toThrow('database unavailable');
    expect(resources.tracked.stations).toEqual(new Set(['7']));
  });
});
