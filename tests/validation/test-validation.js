/**
 * Babbel Validation Tests - Node.js
 * Test validation and edge cases
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class ValidationTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
    }
    
    /**
     * Test API validation
     */
    async testApiValidation() {
        this.printSection('Testing API Validation');
        
        // Test various validation scenarios
        const validationTests = [
            {
                endpoint: '/stations',
                data: {},
                description: 'Empty station data'
            },
            {
                endpoint: '/voices',
                data: { name: '' },
                description: 'Empty voice name'
            },
            {
                endpoint: '/users',
                data: { username: 'a' },
                description: 'Short username'
            }
        ];
        
        for (const test of validationTests) {
            this.printInfo(`Testing: ${test.description}`);
            
            const response = await this.apiCall('POST', test.endpoint, test.data);
            
            if (this.assertions.assertHttpError(response.status, test.description)) {
                this.printSuccess(`Validation correctly rejected: ${test.description}`);
            } else {
                this.printError(`Validation should have rejected: ${test.description}`);
            }
        }
        
        return true;
    }
    
    /**
     * Test edge cases
     */
    async testEdgeCases() {
        this.printSection('Testing Edge Cases');
        
        // Test accessing non-existent resources
        const response = await this.apiCall('GET', '/stations/99999');
        
        if (this.assertions.assertStatusCode(response.status, 404, 'Non-existent resource')) {
            this.printSuccess('Non-existent resource correctly returns 404');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up validation tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up validation tests...');
        return true;
    }
    
    /**
     * Restore admin session (compatibility helper)
     */
    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            return await this.apiLogin();
        }
        return true;
    }
    
    /**
     * Main test runner
     */
    async run() {
        this.printHeader('Validation Tests');
        
        await this.setup();
        
        const tests = [
            'testApiValidation',
            'testEdgeCases'
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
        
        await this.cleanup();
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All validation tests passed!');
            return true;
        } else {
            this.printError(`${failed} validation tests failed`);
            return false;
        }
    }
}

module.exports = ValidationTests;