// Tracks integration-test resources for dependency-safe cleanup.

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

  constructor(apiHelper) {
    this.api = apiHelper;
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
      console.warn(`ResourceManager: unknown resource type '${type}' (known: ${Object.keys(this.tracked).join(', ')})`);
      return;
    }
    this.tracked[type].add(String(id));
  }

  /** @returns {Promise<{deleted: number, failed: number}>} */
  async cleanupAll() {
    let deleted = 0;
    let failed = 0;

    for (const type of ResourceManager.CLEANUP_ORDER) {
      const result = await this.cleanupType(type);
      deleted += result.deleted;
      failed += result.failed;
    }

    return { deleted, failed };
  }

  /**
   * @param {string} type
   * @returns {Promise<{deleted: number, failed: number}>}
   */
  async cleanupType(type) {
    const ids = this.tracked[type];
    if (!ids || ids.size === 0) {
      return { deleted: 0, failed: 0 };
    }

    const endpoint = ResourceManager.ENDPOINTS[type];
    if (!endpoint) {
      return { deleted: 0, failed: ids.size };
    }

    let deleted = 0;
    let failed = 0;

    for (const id of ids) {
      try {
        const response = await this.api.apiCall('DELETE', `${endpoint}/${id}`);

        if (response.status === 204 || response.status === 200 || response.status === 404) {
          // Already absent is a successful cleanup.
          deleted++;
        } else {
          failed++;
        }
      } catch (error) {
        failed++;
      }
    }

    this.tracked[type].clear();

    return { deleted, failed };
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
