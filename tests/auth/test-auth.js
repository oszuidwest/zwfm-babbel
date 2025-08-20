/**
 * Babbel Authentication Tests - Node.js
 * Test basic authentication functionality
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class AuthTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
    }
    
    /**
     * Test successful login
     */
    async testSuccessfulLogin() {
        this.printSection('Testing Successful Login');
        
        // Test admin login
        if (await this.apiLogin('admin', 'admin')) {
            this.printSuccess('Admin login successful');
            
            // Verify session is active
            if (await this.isSessionActive()) {
                this.printSuccess('Session is active after login');
            } else {
                this.printError('Session not active after successful login');
                return false;
            }
            
            // Get session info
            const sessionInfo = await this.getCurrentSession();
            if (sessionInfo) {
                const username = this.parseJsonField(sessionInfo, 'username');
                const role = this.parseJsonField(sessionInfo, 'role');
                
                this.assertions.assertJsonFieldEquals(sessionInfo, 'username', 'admin', 'Session username');
                this.assertions.assertJsonFieldEquals(sessionInfo, 'role', 'admin', 'Session role');
            } else {
                this.printError('Could not retrieve session information');
                return false;
            }
        } else {
            this.printError('Admin login failed');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test login failures
     */
    async testLoginFailures() {
        this.printSection('Testing Login Failures');
        
        // Test with invalid username
        if (await this.testLoginCredentials('nonexistent', 'password', 401)) {
            this.printSuccess('Invalid username correctly rejected');
        } else {
            this.printError('Invalid username test failed');
            return false;
        }
        
        // Test with invalid password
        if (await this.testLoginCredentials('admin', 'wrongpassword', 401)) {
            this.printSuccess('Invalid password correctly rejected');
        } else {
            this.printError('Invalid password test failed');
            return false;
        }
        
        // Test with empty credentials
        const response = await this.apiCall('POST', '/sessions', {});
        
        if (this.assertions.assertHttpError(response.status, 'Empty credentials')) {
            this.printSuccess('Empty credentials correctly rejected');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test session management
     */
    async testSessionManagement() {
        this.printSection('Testing Session Management');
        
        // Login to create session
        if (!(await this.apiLogin('admin', 'admin'))) {
            this.printError('Could not login for session tests');
            return false;
        }
        
        // Test getting current session
        const sessionInfo = await this.getCurrentSession();
        if (this.assertions.assertNotEmpty(sessionInfo, 'Current session info')) {
            this.printSuccess('Can retrieve current session');
        } else {
            return false;
        }
        
        // Test session logout
        if (await this.apiLogout()) {
            this.printSuccess('Logout successful');
            
            // Verify session is destroyed
            if (!(await this.isSessionActive())) {
                this.printSuccess('Session correctly destroyed after logout');
            } else {
                this.printError('Session still active after logout');
                return false;
            }
            
            // Test accessing protected endpoint after logout
            const response = await this.apiCall('GET', '/sessions/current');
            
            if (this.assertions.assertHttpError(response.status, 'Access after logout')) {
                this.printSuccess('Protected endpoint correctly rejects after logout');
            } else {
                return false;
            }
        } else {
            this.printError('Logout failed');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test unauthorized access
     */
    async testUnauthorizedAccess() {
        this.printSection('Testing Unauthorized Access');
        
        // Ensure we're logged out
        await this.apiLogout();
        
        const protectedEndpoints = [
            { method: 'GET', endpoint: '/stations' },
            { method: 'GET', endpoint: '/voices' },
            { method: 'GET', endpoint: '/stories' },
            { method: 'GET', endpoint: '/users' },
            { method: 'GET', endpoint: '/sessions/current' }
        ];
        
        for (const endpointSpec of protectedEndpoints) {
            const { method, endpoint } = endpointSpec;
            
            this.printInfo(`Testing unauthorized access to ${method} ${endpoint}`);
            
            const response = await this.apiCall(method, endpoint);
            
            if (this.assertions.assertHttpError(response.status, `Unauthorized ${method} ${endpoint}`)) {
                this.printSuccess(`Unauthorized access correctly rejected for ${endpoint}`);
            } else {
                this.printError(`Unauthorized access unexpectedly allowed for ${endpoint}`);
            }
        }
        
        return true;
    }
    
    /**
     * Test invalid session token
     */
    async testInvalidSession() {
        this.printSection('Testing Invalid Session Token');
        
        // Clear cookies and set invalid session
        await this.clearCookies();
        
        // Test with completely invalid session token
        const response1 = await this.http({
            method: 'get',
            url: `${this.apiUrl}/sessions/current`,
            headers: {
                'Cookie': 'babbel_session=invalid_session_token_12345'
            }
        });
        
        if (this.assertions.assertHttpError(response1.status, 'Invalid session token')) {
            this.printSuccess('Invalid session token correctly rejected');
        } else {
            return false;
        }
        
        // Test with malformed cookie
        const response2 = await this.http({
            method: 'get',
            url: `${this.apiUrl}/sessions/current`,
            headers: {
                'Cookie': 'babbel_session=malformed'
            }
        });
        
        if (this.assertions.assertHttpError(response2.status, 'Malformed session token')) {
            this.printSuccess('Malformed session token correctly rejected');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test auth config endpoint
     */
    async testAuthConfig() {
        this.printSection('Testing Auth Configuration');
        
        // Auth config should be publicly accessible
        const response = await this.http({
            method: 'get',
            url: `${this.apiUrl}/auth/config`
        });
        
        if (this.assertions.assertStatusCode(response.status, 200, 'Auth config endpoint')) {
            this.printSuccess('Auth config endpoint accessible');
            
            // Should have expected fields
            if (this.assertions.assertJsonField(response.data, 'local_auth_enabled', 'Local auth enabled field')) {
                const localAuth = this.parseJsonField(response.data, 'local_auth_enabled');
                this.printInfo(`Local auth enabled: ${localAuth}`);
            }
            
            if (this.assertions.assertJsonField(response.data, 'oauth_enabled', 'OAuth enabled field')) {
                const oauth = this.parseJsonField(response.data, 'oauth_enabled');
                this.printInfo(`OAuth enabled: ${oauth}`);
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Helper function to test login credentials
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
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up authentication tests...');
        // Ensure we start with a clean session
        await this.apiLogout();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up authentication tests...');
        // Ensure we're logged back in as admin for other tests
        await this.apiLogin('admin', 'admin');
        return true;
    }
    
    /**
     * Main test runner
     */
    async run() {
        this.printHeader('Authentication Tests');
        
        await this.setup();
        
        const tests = [
            'testAuthConfig',
            'testLoginFailures',
            'testSuccessfulLogin',
            'testSessionManagement',
            'testUnauthorizedAccess',
            'testInvalidSession'
        ];
        
        let failed = 0;
        
        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error(''); // Add spacing between tests
        }
        
        await this.cleanup();
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All authentication tests passed!');
            return true;
        } else {
            this.printError(`${failed} authentication tests failed`);
            return false;
        }
    }
}

module.exports = AuthTests;

// Run tests if executed directly
if (require.main === module) {
    const test = new AuthTests();
    test.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}