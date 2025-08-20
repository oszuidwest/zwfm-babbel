// Test suspended user login prevention.
// Verifies that suspended users cannot authenticate and can be restored.

const BaseTest = require('../lib/BaseTest');

class SuspendedLoginTest extends BaseTest {
    constructor() {
        super();
    }
    
    /**
     * Tests the complete suspension and restoration workflow.
     * Verifies users can login normally, cannot login when suspended, and can login again when restored.
     */
    async testSuspendedUserCannotLogin() {
        this.printSection('Testing Suspended User Login Prevention');
        
        // Login as admin to create and manage test users.
        this.printInfo('Logging in as admin...');
        if (!await this.apiLogin()) {
            this.printError('Failed to login as admin');
            return false;
        }
        
        // Create a test user for suspension testing.
        this.printInfo('Creating test user...');
        const timestamp = Date.now();
        const username = `suspendtest${timestamp}`;
        const password = 'TestPass123!';
        const email = `suspend${timestamp}@test.com`;
        
        const createResponse = await this.apiCall('POST', '/users', {
            username: username,
            full_name: 'Suspension Test User',
            password: password,
            email: email,
            role: 'editor'
        });
        
        if (createResponse.status !== 201) {
            this.printError(`Failed to create test user: ${createResponse.status}`);
            return false;
        }
        
        const userId = this.parseJsonField(createResponse.data, 'id');
        this.printSuccess(`Created test user (ID: ${userId})`);
        
        // Logout admin to test user login.
        await this.apiLogout();
        
        // Test 1: Verify user can login normally before suspension.
        this.printInfo('Testing normal login before suspension...');
        const loginResponse = await this.apiCall('POST', '/sessions', {
            username: username,
            password: password
        });
        
        if (loginResponse.status === 201) {
            this.printSuccess('User can login normally before suspension');
        } else {
            this.printError(`User cannot login even before suspension: ${loginResponse.status}`);
            return false;
        }
        
        // Logout the test user after successful login.
        await this.apiLogout();
        
        // Re-authenticate as admin to perform suspension.
        this.printInfo('Logging back as admin to suspend user...');
        if (!await this.apiLogin()) {
            this.printError('Failed to login as admin');
            return false;
        }
        
        // Suspend the test user account.
        this.printInfo('Suspending the user...');
        const suspendResponse = await this.apiCall('PUT', `/users/${userId}`, {
            suspended: true
        });
        
        if (suspendResponse.status !== 200) {
            this.printError(`Failed to suspend user: ${suspendResponse.status}`);
            return false;
        }
        
        // Verify the user account shows suspended status.
        const getUserResponse = await this.apiCall('GET', `/users/${userId}`);
        if (getUserResponse.status === 200) {
            const userData = getUserResponse.data;
            if (userData.suspended_at) {
                this.printSuccess(`User suspended at: ${userData.suspended_at}`);
            } else {
                this.printError('User suspension not reflected in data');
                return false;
            }
        } else {
            this.printError(`Failed to get user data: ${getUserResponse.status}`);
            return false;
        }
        
        // Logout admin to test user login.
        await this.apiLogout();
        
        // Test 2: Verify suspended user cannot login.
        this.printInfo('Testing suspended user login (should fail)...');
        const suspendedLoginResponse = await this.apiCall('POST', '/sessions', {
            username: username,
            password: password
        });
        
        if (suspendedLoginResponse.status === 401) {
            this.printSuccess('Suspended user correctly prevented from logging in');
            
            // Verify appropriate error message is returned.
            const errorMsg = this.extractErrorMessage(suspendedLoginResponse.data);
            if (errorMsg && errorMsg.toLowerCase().includes('suspend')) {
                this.printSuccess(`Appropriate error message: ${errorMsg}`);
            } else {
                this.printWarning(`Generic error message: ${errorMsg || 'none'}`);
            }
        } else {
            this.printError(`Suspended user was able to login! Status: ${suspendedLoginResponse.status}`);
            return false;
        }
        
        // Test 3: Restore user and verify login functionality is restored.
        this.printInfo('Testing user restoration...');
        
        // Re-authenticate as admin to perform restoration.
        if (!await this.apiLogin()) {
            this.printError('Failed to login as admin');
            return false;
        }
        
        // Restore the suspended user account.
        this.printInfo('Restoring the user...');
        const restoreResponse = await this.apiCall('PUT', `/users/${userId}`, {
            suspended: false
        });
        
        if (restoreResponse.status !== 200) {
            this.printError(`Failed to restore user: ${restoreResponse.status}`);
            return false;
        }
        
        // Logout admin to test user login.
        await this.apiLogout();
        
        // Verify that restored user can login successfully.
        this.printInfo('Testing restored user can login...');
        const restoredLoginResponse = await this.apiCall('POST', '/sessions', {
            username: username,
            password: password
        });
        
        if (restoredLoginResponse.status === 201) {
            this.printSuccess('Restored user can login successfully');
        } else {
            this.printError(`Restored user cannot login: ${restoredLoginResponse.status}`);
            return false;
        }
        
        // Clean up by deleting the test user account.
        await this.apiLogout();
        if (await this.apiLogin()) {
            await this.apiCall('DELETE', `/users/${userId}`);
            this.printInfo('Cleaned up test user');
        }
        
        return true;
    }
    
    /**
     * Main test runner for suspended login tests.
     * @returns {Promise<boolean>} True if all tests passed.
     */
    async run() {
        this.printHeader('Suspended User Login Test');
        
        const tests = [
            'testSuspendedUserCannotLogin'
        ];
        
        let failed = 0;
        
        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error('');
        }
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All suspended login tests passed!');
            return true;
        } else {
            this.printError(`${failed} suspended login tests failed`);
            return false;
        }
    }
}

module.exports = SuspendedLoginTest;

// Run tests if executed directly
if (require.main === module) {
    const test = new SuspendedLoginTest();
    test.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}