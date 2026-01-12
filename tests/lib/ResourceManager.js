// Resource manager for Babbel API tests.
// Handles tracking and cleanup of test resources in the correct order.

class ResourceManager {
    /**
     * Cleanup order based on foreign key constraints.
     * Resources that reference other resources must be deleted first.
     */
    static CLEANUP_ORDER = [
        'bulletins',      // References stories
        'stories',        // References voices, stations (via story_stations)
        'stationVoices',  // References voices, stations
        'voices',         // No dependencies on other tracked resources
        'stations'        // Base resource, deleted last
    ];

    /**
     * Maps resource type to API endpoint.
     */
    static ENDPOINTS = {
        bulletins: '/bulletins',
        stories: '/stories',
        stationVoices: '/station-voices',
        voices: '/voices',
        stations: '/stations'
    };

    constructor(apiHelper) {
        this.api = apiHelper;
        this.tracked = {
            stations: new Set(),
            voices: new Set(),
            stationVoices: new Set(),
            stories: new Set(),
            bulletins: new Set()
        };
    }

    /**
     * Tracks a resource for cleanup.
     * @param {string} type - Resource type (stations, voices, stories, stationVoices, bulletins).
     * @param {string|number} id - Resource ID.
     */
    track(type, id) {
        if (!this.tracked[type]) {
            return;
        }
        this.tracked[type].add(String(id));
    }

    /**
     * Gets tracked IDs for a resource type.
     * @param {string} type - Resource type.
     * @returns {Array<string>} Array of tracked IDs.
     */
    getTracked(type) {
        if (!this.tracked[type]) {
            return [];
        }
        return Array.from(this.tracked[type]);
    }

    /**
     * Gets count of tracked resources.
     * @returns {Object} Counts per resource type.
     */
    getCounts() {
        const counts = {};
        for (const [type, set] of Object.entries(this.tracked)) {
            counts[type] = set.size;
        }
        return counts;
    }

    /**
     * Cleans up all tracked resources in the correct order.
     * @returns {Promise<{deleted: number, failed: number}>} Cleanup statistics.
     */
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
     * Cleans up all resources of a specific type.
     * @param {string} type - Resource type to clean up.
     * @returns {Promise<{deleted: number, failed: number}>} Cleanup statistics.
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
                    // 404 means already deleted, consider it a success
                    deleted++;
                } else {
                    failed++;
                }
            } catch (error) {
                failed++;
                // Ignore cleanup errors but count them
            }
        }

        // Clear tracked IDs after cleanup
        this.tracked[type].clear();

        return { deleted, failed };
    }

    /**
     * Removes a specific ID from tracking (e.g., after manual deletion in test).
     * @param {string} type - Resource type.
     * @param {string|number} id - Resource ID.
     */
    untrack(type, id) {
        if (this.tracked[type]) {
            this.tracked[type].delete(String(id));
        }
    }

    /**
     * Clears all tracked resources without deleting them.
     * Useful for tests that handle their own cleanup.
     */
    clearTracking() {
        for (const type of Object.keys(this.tracked)) {
            this.tracked[type].clear();
        }
    }
}

module.exports = ResourceManager;
