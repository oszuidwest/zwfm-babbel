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

  async cleanupAll() {
    for (const type of ResourceManager.CLEANUP_ORDER) {
      // Bulletins have no DELETE endpoint; the database pass below removes
      // them together with jobs and joins belonging to tracked stations.
      if (type === 'bulletins') continue;
      await this.cleanupType(type);
    }

    this.cleanupDatabase();
    for (const ids of Object.values(this.tracked)) ids.clear();
  }

  cleanupDatabase() {
    const ids = type => [...this.tracked[type]].map(id => sqlInteger(id, `${type} ID`));
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
   */
  async cleanupType(type) {
    const ids = this.tracked[type];
    const endpoint = ResourceManager.ENDPOINTS[type];

    for (const id of ids) {
      try {
        await this.api.apiCall('DELETE', `${endpoint}/${id}`);
      } catch {
        // The database fallback below remains authoritative for cleanup.
      }
    }
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
