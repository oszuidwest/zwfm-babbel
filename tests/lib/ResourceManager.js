// Tracks integration-test resources for dependency-safe cleanup.
const { createMySQLExecutor, sqlInteger } = require('./MySQLHelper');

class ResourceManager {
  static CLEANUP_ORDER = [
    'bulletins',
    'stories',
    'stationVoices',
    'voices',
    'stations',
    'users'
  ];

  static ENDPOINTS = {
    bulletins: '/bulletins',
    stories: '/stories',
    stationVoices: '/station-voices',
    voices: '/voices',
    stations: '/stations',
    users: '/users'
  };

  constructor(apiHelper, mysql = createMySQLExecutor()) {
    this.api = apiHelper;
    this.mysql = mysql;
    this.tracked = {
      stations: new Set(),
      voices: new Set(),
      stationVoices: new Set(),
      stories: new Set(),
      bulletins: new Set(),
      users: new Set()
    };
  }

  /**
   * @param {string} type
   * @param {string|number} id
   */
  track(type, id) {
    if (!this.tracked[type]) {
      throw new Error(`ResourceManager: unknown resource type '${type}' (known: ${Object.keys(this.tracked).join(', ')})`);
    }
    if (id === undefined || id === null || id === '') {
      throw new Error(`ResourceManager: cannot track ${type} without an ID`);
    }
    this.tracked[type].add(String(id));
  }

  /** @returns {Promise<{deleted: number, failed: number, errors: string[]}>} */
  async cleanupAll() {
    const snapshot = Object.fromEntries(
      Object.entries(this.tracked).map(([type, ids]) => [type, [...ids]])
    );
    let deleted = 0;

    for (const type of ResourceManager.CLEANUP_ORDER) {
      // Bulletins have no DELETE endpoint; the database pass below removes
      // them together with jobs and joins belonging to tracked stations.
      if (type === 'bulletins') continue;
      deleted += await this.cleanupType(type);
    }

    try {
      this.cleanupDatabase(snapshot);
      for (const ids of Object.values(this.tracked)) ids.clear();
      return { deleted, failed: 0, errors: [] };
    } catch (error) {
      return { deleted, failed: 1, errors: [error.message] };
    }
  }

  cleanupDatabase(snapshot) {
    const ids = type => snapshot[type].map(id => sqlInteger(id, `${type} ID`));
    const whereIDs = (column, values) => values.length > 0 ? `${column} IN (${values.join(', ')})` : null;
    const statements = [];
    const bulletinPredicates = [
      whereIDs('id', ids('bulletins')),
      whereIDs('station_id', ids('stations'))
    ].filter(Boolean);
    if (bulletinPredicates.length > 0) {
      statements.push(`DELETE FROM bulletins WHERE ${bulletinPredicates.join(' OR ')}`);
    }
    for (const [type, table] of [
      ['stories', 'stories'],
      ['stationVoices', 'station_voices'],
      ['voices', 'voices'],
      ['stations', 'stations'],
      ['users', 'users']
    ]) {
      const predicate = whereIDs('id', ids(type));
      if (predicate) statements.push(`DELETE FROM ${table} WHERE ${predicate}`);
    }
    if (statements.length > 0) {
      this.mysql.execSQLScript(`START TRANSACTION;\n${statements.join(';\n')};\nCOMMIT;\n`);
    }
  }

  /**
   * @param {string} type
   * @returns {Promise<number>} Number removed (or already absent) via the API.
   */
  async cleanupType(type) {
    const ids = this.tracked[type];
    if (!ids || ids.size === 0) {
      return 0;
    }

    const endpoint = ResourceManager.ENDPOINTS[type];
    if (!endpoint) {
      return 0;
    }

    let deleted = 0;

    for (const id of ids) {
      try {
        const response = await this.api.apiCall('DELETE', `${endpoint}/${id}`);

        if (response.status === 204 || response.status === 200 || response.status === 404) {
          // Already absent is a successful cleanup.
          deleted++;
        }
      } catch {
        // The database fallback below remains authoritative for cleanup.
      }
    }

    return deleted;
  }

  /**
   * @param {string} type
   * @param {string|number} id
   */
  untrack(type, id) {
    if (this.tracked[type]) {
      this.tracked[type].delete(String(id));
    }
  }
}

module.exports = ResourceManager;
