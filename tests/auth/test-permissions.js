// Babbel permissions tests.
// Tests role-based access control (RBAC) functionality across different user roles.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class PermissionsTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Store user IDs for cleanup after tests.
        this.testUserId = '';
        this.testEditorId = '';
        this.testViewerId = '';
    }
    
    /**
     * Creates a user and returns their ID.
     * @param {string} username - Username for the new user.
     * @param {string} fullName - Full name of the user.
     * @param {string} password - Password for the user.
     * @param {string} role - User role (admin, editor, viewer).
     * @returns {Promise<string|null>} User ID or null if creation failed.
     */
    async createUserAndGetId(username, fullName, password, role) {
        this.printInfo(`Creating user: ${username}`);
        
        const response = await this.apiCall('POST', '/users', {
            username,
            full_name: fullName,
            password,
            role
        });
        
        if (response.status === 201) {
            // API returns {id: X, message: "..."} on creation
            const userId = this.parseJsonField(response.data, 'id');
            
            if (userId) {
                this.printSuccess(`User created successfully (ID: ${userId})`);
                return userId;
            } else {
                this.printError('Could not extract user ID from response');
                return null;
            }
        } else if (response.status === 409) {
            // User already exists, try to find it
            this.printInfo(`User ${username} already exists, fetching ID...`);
            const userResponse = await this.apiCall('GET', '/users');
            
            if (userResponse.status === 200 && userResponse.data.data) {
                for (const user of userResponse.data.data) {
                    if (user.username === username) {
                        this.printInfo(`Found existing user ID: ${user.id}`);
                        return String(user.id);
                    }
                }
            }
            
            this.printError('User exists but could not find ID');
            return null;
        } else {
            this.printError(`Failed to create user (HTTP ${response.status})`);
            this.printError(`Response: ${JSON.stringify(response.data)}`);
            return null;
        }
    }
    
    /**
     * Tests that admin users have full access to all operations.
     */
    async testAdminPermissions() {
        this.printSection('Testing Admin Permissions');
        
        // Ensure admin session is active for user creation.
        if (!(await this.restoreAdminSession())) {
            this.printError('Could not establish admin session');
            return false;
        }
        
        // Verify admin can create users.
        this.printInfo('Testing admin can create users...');
        const response = await this.apiCall('POST', '/users', {
            username: 'testadminuser',
            full_name: 'Test Admin User',
            password: 'testpass123',
            role: 'editor'
        });
        
        if (response.status === 201) {
            // API returns {id: X, message: "..."} on creation
            this.testUserId = this.parseJsonField(response.data, 'id');
            
            if (this.testUserId) {
                this.printSuccess(`Admin can create users (ID: ${this.testUserId})`);
            } else {
                this.printWarning('User created but could not get ID from response');
                this.testUserId = '';
            }
        } else {
            this.printError(`Admin cannot create users (HTTP: ${response.status})`);
            return false;
        }
        
        // Admin should be able to list users
        this.printInfo('Testing admin can list users...');
        const listResponse = await this.apiCall('GET', '/users');
        if (this.assertions.checkResponse(listResponse, 200, 'Admin list users')) {
            const userCount = listResponse.data.data ? listResponse.data.data.length : 0;
            this.printSuccess(`Admin can list users (found ${userCount} users)`);
        } else {
            return false;
        }
        
        // Admin should be able to update users
        if (this.testUserId) {
            this.printInfo('Testing admin can update users...');
            const updateResponse = await this.apiCall('PUT', `/users/${this.testUserId}`, {
                username: 'testadminuser',
                full_name: 'Updated Test User',
                role: 'viewer'
            });
            
            if (this.assertions.checkResponse(updateResponse, 200, 'Admin update user')) {
                this.printSuccess('Admin can update users');
            } else {
                return false;
            }
        }
        
        // Admin should be able to delete users (we'll test this in cleanup)
        this.printSuccess('Admin permissions verified');
        return true;
    }
    
    /**
     * Tests that editor users can read and modify content but not manage users.
     */
    async testEditorPermissions() {
        this.printSection('Testing Editor Permissions');
        
        // First create an editor user as admin
        await this.restoreAdminSession();
        
        // Try to create or find existing editor user
        this.testEditorId = await this.createUserAndGetId('testeditor', 'Test Editor', 'testpass123', 'editor');
        if (!this.testEditorId) {
            this.printError('Could not create or find editor user');
            return false;
        } else {
            this.printSuccess(`Using editor user (ID: ${this.testEditorId})`);
        }
        
        // Login as editor
        const backupCookie = await this.switchToUser('testeditor', 'testpass123');
        if (!backupCookie) {
            this.printError('Could not login as editor');
            return false;
        }
        
        // Editor should be able to read resources
        this.printInfo('Testing editor can read resources...');
        
        const readEndpoints = [
            '/stations',
            '/voices',
            '/stories',
            '/bulletins'
        ];
        
        for (const endpoint of readEndpoints) {
            const response = await this.apiCall('GET', endpoint);
            if (this.assertions.checkResponse(response, 200, `Editor read ${endpoint}`)) {
                this.printSuccess(`Editor can read ${endpoint}`);
            } else {
                this.printError(`Editor cannot read ${endpoint}`);
                await this.restoreFromBackup(backupCookie);
                return false;
            }
        }
        
        // Editor should be able to create/update content
        this.printInfo('Testing editor can create content...');
        
        // Test creating a station
        const stationResponse = await this.apiCall('POST', '/stations', {
            name: 'Editor Test Station',
            max_stories_per_block: 5,
            pause_seconds: 2.0
        });
        
        if (this.assertions.checkResponse(stationResponse, 201, 'Editor create station')) {
            this.printSuccess('Editor can create stations');
        } else {
            this.printError('Editor cannot create stations');
        }
        
        // Editor should NOT be able to manage users
        this.printInfo('Testing editor cannot manage users...');
        
        const userCreateResponse = await this.apiCall('POST', '/users', {
            username: 'unauthorized',
            full_name: 'Unauthorized User',
            password: 'test',
            role: 'viewer'
        });
        
        if (this.assertions.assertHttpError(userCreateResponse.status, 'Editor create user')) {
            this.printSuccess('Editor correctly denied user creation');
        } else {
            this.printError('Editor unexpectedly allowed to create users');
            await this.restoreFromBackup(backupCookie);
            return false;
        }
        
        // Editor should NOT be able to delete users
        const userDeleteResponse = await this.apiCall('DELETE', '/users/1');
        if (this.assertions.assertHttpError(userDeleteResponse.status, 'Editor delete user')) {
            this.printSuccess('Editor correctly denied user deletion');
        } else {
            this.printError('Editor unexpectedly allowed to delete users');
            await this.restoreFromBackup(backupCookie);
            return false;
        }
        
        // Return to admin session.
        await this.restoreFromBackup(backupCookie);
        this.printSuccess('Editor permissions verified');
        return true;
    }
    
    /**
     * Tests that viewer users have read-only access to content.
     */
    async testViewerPermissions() {
        this.printSection('Testing Viewer Permissions');
        
        // First create a viewer user as admin
        await this.restoreAdminSession();
        
        // Try to create or find existing viewer user
        this.testViewerId = await this.createUserAndGetId('testviewer', 'Test Viewer', 'testpass123', 'viewer');
        if (!this.testViewerId) {
            this.printError('Could not create or find viewer user');
            return false;
        } else {
            this.printSuccess(`Using viewer user (ID: ${this.testViewerId})`);
        }
        
        // Login as viewer
        const backupCookie = await this.switchToUser('testviewer', 'testpass123');
        if (!backupCookie) {
            this.printError('Could not login as viewer');
            return false;
        }
        
        // Viewer should be able to read resources
        this.printInfo('Testing viewer can read resources...');
        
        const readEndpoints = [
            '/stations',
            '/voices',
            '/stories',
            '/bulletins'
        ];
        
        for (const endpoint of readEndpoints) {
            const response = await this.apiCall('GET', endpoint);
            if (this.assertions.checkResponse(response, 200, `Viewer read ${endpoint}`)) {
                this.printSuccess(`Viewer can read ${endpoint}`);
            } else {
                this.printError(`Viewer cannot read ${endpoint}`);
                await this.restoreFromBackup(backupCookie);
                return false;
            }
        }
        
        // Viewer should NOT be able to create content
        this.printInfo('Testing viewer cannot create content...');
        
        const createTests = [
            {
                method: 'POST',
                endpoint: '/stations',
                data: { name: 'Viewer Test Station', max_stories_per_block: 5, pause_seconds: 2.0 }
            },
            {
                method: 'POST',
                endpoint: '/voices',
                data: { name: 'Viewer Test Voice' }
            },
            {
                method: 'POST',
                endpoint: '/stories',
                data: { title: 'Viewer Test Story', content: 'Test', voice_id: 1 }
            }
        ];
        
        for (const test of createTests) {
            const response = await this.apiCall(test.method, test.endpoint, test.data);
            
            if (this.assertions.assertHttpError(response.status, `Viewer ${test.method} ${test.endpoint}`)) {
                this.printSuccess(`Viewer correctly denied ${test.method} ${test.endpoint}`);
            } else {
                this.printError(`Viewer unexpectedly allowed ${test.method} ${test.endpoint}`);
            }
        }
        
        // Viewer should NOT be able to manage users
        this.printInfo('Testing viewer cannot manage users...');
        
        const usersResponse = await this.apiCall('GET', '/users');
        if (this.assertions.assertHttpError(usersResponse.status, 'Viewer list users')) {
            this.printSuccess('Viewer correctly denied user list access');
        } else {
            this.printError('Viewer unexpectedly allowed to list users');
        }
        
        // Return to admin session.
        await this.restoreFromBackup(backupCookie);
        this.printSuccess('Viewer permissions verified');
        return true;
    }
    
    /**
     * Tests that suspended users cannot authenticate.
     */
    async testSuspendedUser() {
        this.printSection('Testing Suspended User');
        
        // Create and suspend a user
        await this.restoreAdminSession();
        
        // Try to create or find existing user to suspend
        const suspendedId = await this.createUserAndGetId('suspendeduser', 'Suspended User', 'testpass123', 'editor');
        if (!suspendedId) {
            this.printError('Could not create or find user for suspension test');
            return false;
        } else {
            this.printSuccess(`Using user to suspend (ID: ${suspendedId})`);
        }
        
        // Suspend the user (soft delete)
        const suspendResponse = await this.apiCall('DELETE', `/users/${suspendedId}`);
        if (this.assertions.checkResponse(suspendResponse, 204, 'Suspend user')) {
            this.printSuccess('User suspended successfully');
        } else {
            this.printError('Could not suspend user');
            return false;
        }
        
        // Try to login as suspended user (should fail)
        this.printInfo('Testing suspended user cannot login...');
        if (await this.testLoginCredentials('suspendeduser', 'testpass123', 401)) {
            this.printSuccess('Suspended user correctly cannot login');
        } else {
            this.printError('Suspended user unexpectedly allowed to login');
            return false;
        }
        
        return true;
    }
    
    // Helper Methods
    
    /**
     * Restores admin session for subsequent operations.
     * @returns {Promise<boolean>} True if admin session was restored.
     */
    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            this.printInfo('Restoring admin session');
            return await this.apiLogin();
        } else {
            if (await this.checkAdminPrivileges()) {
                this.printInfo('Admin session already active');
                return true;
            } else {
                this.printInfo('Non-admin session active, re-logging as admin');
                await this.apiLogout();
                return await this.apiLogin();
            }
        }
    }
    
    /**
     * Checks if current session has admin privileges.
     * @returns {Promise<boolean>} True if session has admin access.
     */
    async checkAdminPrivileges() {
        // Try to access an admin-only endpoint (like listing users)
        const response = await this.apiCall('GET', '/users');
        return response.status === 200;
    }
    
    /**
     * Switches to a different user session.
     * @param {string} username - Username to switch to.
     * @param {string} password - Password for the user.
     * @returns {Promise<Object|null>} Backup session info or null if failed.
     */
    async switchToUser(username, password) {
        // Save current session info (simplified approach)
        const currentSession = await this.getCurrentSession();
        
        // Login as different user
        if (await this.apiLogin(username, password)) {
            return currentSession; // Return previous session as backup
        } else {
            return null;
        }
    }
    
    /**
     * Restores session from backup.
     * @param {Object} backupSession - Previous session data.
     * @returns {Promise<boolean>} True if session was restored.
     */
    async restoreFromBackup(backupSession) {
        this.printInfo('Session restored from backup');
        return await this.apiLogin(); // Simplified: just re-login as admin
    }
    
    /**
     * Tests login credentials with expected result.
     * @param {string} username - Username to test.
     * @param {string} password - Password to test.
     * @param {number} expectedStatus - Expected HTTP status code (default: 201).
     * @returns {Promise<boolean>} True if result matches expectation.
     */
    async testLoginCredentials(username, password, expectedStatus = 201) {
        const response = await this.apiCall('POST', '/sessions', {
            username,
            password
        });
        
        if (response.status === expectedStatus) {
            if (expectedStatus === 201) {
                this.printSuccess(`Login successful for ${username}`);
                // Clean up the successful login
                await this.apiLogout();
            } else {
                this.printSuccess(`Login correctly failed for ${username} (HTTP ${response.status})`);
            }
            return true;
        } else {
            this.printError(`Unexpected login result for ${username}: expected ${expectedStatus}, got ${response.status}`);
            return false;
        }
    }
    
    // Setup and Cleanup
    
    /**
     * Sets up permission tests by ensuring admin session.
     * @returns {Promise<boolean>} True if setup succeeded.
     */
    async setup() {
        this.printInfo('Setting up permission tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleans up test users and resources.
     * @returns {Promise<boolean>} True if cleanup succeeded.
     */
    async cleanup() {
        this.printInfo('Cleaning up permission tests...');
        
        // Ensure we're admin
        await this.restoreAdminSession();
        
        // Clean up test users
        if (this.testUserId) {
            try {
                await this.apiCall('DELETE', `/users/${this.testUserId}`);
                this.printInfo(`Cleaned up test user: ${this.testUserId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        if (this.testEditorId) {
            try {
                await this.apiCall('DELETE', `/users/${this.testEditorId}`);
                this.printInfo(`Cleaned up editor user: ${this.testEditorId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        if (this.testViewerId) {
            try {
                await this.apiCall('DELETE', `/users/${this.testViewerId}`);
                this.printInfo(`Cleaned up viewer user: ${this.testViewerId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up any test stations created
        try {
            const stationsResponse = await this.apiCall('GET', '/stations');
            if (stationsResponse.status === 200 && stationsResponse.data.data) {
                for (const station of stationsResponse.data.data) {
                    if (station.name && station.name.includes('Test')) {
                        await this.apiCall('DELETE', `/stations/${station.id}`);
                        this.printInfo(`Cleaned up test station: ${station.id}`);
                    }
                }
            }
        } catch (error) {
            // Ignore cleanup errors
        }
        
        return true;
    }
    
    /**
     * Main test runner for permission tests.
     * @returns {Promise<boolean>} True if all tests passed.
     */
    async run() {
        this.printHeader('Permission Tests');
        
        await this.setup();
        
        const tests = [
            'testAdminPermissions',
            'testEditorPermissions',
            'testViewerPermissions',
            'testSuspendedUser'
        ];
        
        let failed = 0;
        
        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error(''); // Add visual spacing between tests.
        }
        
        await this.cleanup();
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All permission tests passed!');
            return true;
        } else {
            this.printError(`${failed} permission tests failed`);
            return false;
        }
    }
}

module.exports = PermissionsTests;
// Run tests if executed directly
if (require.main === module) {
    const TestClass = module.exports;
    const test = new TestClass();
    test.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}
