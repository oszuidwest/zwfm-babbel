// Test assertion functions for Babbel API tests.
// Provides assertion capabilities similar to the bash version with improved error handling.

const fsSync = require('fs');
const { execSync } = require('child_process');

class Assertions {
    constructor(baseTest) {
        this.baseTest = baseTest;
    }
    
    // HTTP Status Assertions
    
    assertStatusCode(actualCode, expectedCode, description = 'HTTP status code') {
        if (actualCode === expectedCode) {
            this.baseTest.printSuccess(`${description}: expected ${expectedCode}, got ${actualCode}`);
            return true;
        } else {
            this.baseTest.printError(`${description}: expected ${expectedCode}, got ${actualCode}`);
            return false;
        }
    }
    
    assertHttpSuccess(httpCode, description = 'HTTP success') {
        if (httpCode >= 200 && httpCode <= 299) {
            this.baseTest.printSuccess(`${description}: HTTP ${httpCode} (success)`);
            return true;
        } else {
            this.baseTest.printError(`${description}: HTTP ${httpCode} (not success)`);
            return false;
        }
    }
    
    assertHttpError(httpCode, description = 'HTTP error') {
        if (httpCode >= 400 && httpCode <= 599) {
            this.baseTest.printSuccess(`${description}: HTTP ${httpCode} (error as expected)`);
            return true;
        } else {
            this.baseTest.printError(`${description}: HTTP ${httpCode} (expected error status)`);
            return false;
        }
    }
    
    // JSON Field Assertions
    
    assertJsonField(data, field, description = null) {
        description = description || `Field ${field}`;
        
        const value = this.baseTest.parseJsonField(data, field);
        
        if (value && value !== 'null') {
            this.baseTest.printSuccess(`${description}: has value '${value}'`);
            return true;
        } else {
            this.baseTest.printError(`${description}: missing or empty`);
            return false;
        }
    }
    
    assertJsonFieldEquals(data, field, expectedValue, description = null) {
        description = description || `Field ${field}`;
        
        const actualValue = this.baseTest.parseJsonField(data, field);
        
        if (actualValue === String(expectedValue)) {
            this.baseTest.printSuccess(`${description}: expected '${expectedValue}', got '${actualValue}'`);
            return true;
        } else {
            this.baseTest.printError(`${description}: expected '${expectedValue}', got '${actualValue}'`);
            return false;
        }
    }
    
    // String Assertions
    
    assertContains(text, substring, description = 'String contains') {
        if (text && text.includes(substring)) {
            this.baseTest.printSuccess(`${description}: contains '${substring}'`);
            return true;
        } else {
            this.baseTest.printError(`${description}: does not contain '${substring}'`);
            return false;
        }
    }
    
    assertNotContains(text, substring, description = 'String does not contain') {
        if (!text || !text.includes(substring)) {
            this.baseTest.printSuccess(`${description}: does not contain '${substring}'`);
            return true;
        } else {
            this.baseTest.printError(`${description}: unexpectedly contains '${substring}'`);
            return false;
        }
    }
    
    assertNotEmpty(value, description = 'Value') {
        if (value && value !== '') {
            this.baseTest.printSuccess(`${description}: is not empty ('${value}')`);
            return true;
        } else {
            this.baseTest.printError(`${description}: is empty`);
            return false;
        }
    }
    
    assertEmpty(value, description = 'Value') {
        if (!value || value === '') {
            this.baseTest.printSuccess(`${description}: is empty`);
            return true;
        } else {
            this.baseTest.printError(`${description}: is not empty ('${value}')`);
            return false;
        }
    }
    
    // File Assertions
    
    assertFileExists(filePath, description = 'File exists') {
        if (fsSync.existsSync(filePath)) {
            this.baseTest.printSuccess(`${description}: ${filePath} exists`);
            return true;
        } else {
            this.baseTest.printError(`${description}: ${filePath} does not exist`);
            return false;
        }
    }
    
    assertFileNotExists(filePath, description = 'File does not exist') {
        if (!fsSync.existsSync(filePath)) {
            this.baseTest.printSuccess(`${description}: ${filePath} does not exist`);
            return true;
        } else {
            this.baseTest.printError(`${description}: ${filePath} exists`);
            return false;
        }
    }
    
    assertFileNotEmpty(filePath, description = 'File not empty') {
        try {
            if (fsSync.existsSync(filePath)) {
                const stats = fsSync.statSync(filePath);
                if (stats.size > 0) {
                    this.baseTest.printSuccess(`${description}: ${filePath} has size ${stats.size} bytes`);
                    return true;
                }
            }
            this.baseTest.printError(`${description}: ${filePath} is empty or does not exist`);
            return false;
        } catch (error) {
            this.baseTest.printError(`${description}: ${filePath} is empty or does not exist`);
            return false;
        }
    }
    
    assertValidAudio(filePath, description = 'Valid audio file') {
        try {
            if (!fsSync.existsSync(filePath)) {
                this.baseTest.printError(`${description}: ${filePath} does not exist`);
                return false;
            }
            
            // Verify audio validity using ffprobe.
            execSync(`ffprobe -v quiet -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "${filePath}"`, 
                { stdio: 'pipe' });
            
            const stats = fsSync.statSync(filePath);
            this.baseTest.printSuccess(`${description}: ${filePath} is valid audio (${stats.size} bytes)`);
            return true;
        } catch (error) {
            this.baseTest.printError(`${description}: ${filePath} is not valid audio`);
            return false;
        }
    }
    
    // Response Checking
    
    checkResponse(response, expectedStatus, description = 'API response') {
        if (this.assertStatusCode(response.status, expectedStatus, description)) {
            // Extract common fields from successful responses.
            if (expectedStatus === 201 || expectedStatus === 200) {
                const id = this.baseTest.parseJsonField(response.data, 'id');
                if (id && id !== 'null') {
                    this.baseTest.printInfo(`Created/Retrieved ID: ${id}`);
                    return id; // Return ID for use in subsequent tests.
                }
            }
            return true;
        } else {
            // Extract error message from failed responses.
            const errorMsg = this.baseTest.extractErrorMessage(response.data);
            if (errorMsg) {
                this.baseTest.printError(`Error message: ${errorMsg}`);
            }
            return false;
        }
    }
    
    // API Endpoint Testing
    
    async testApiEndpoint(method, endpoint, expectedStatus, data = null, description = null) {
        description = description || `${method} ${endpoint}`;
        
        this.baseTest.printInfo(`Testing: ${description}`);
        
        const response = await this.baseTest.apiCall(method, endpoint, data);
        
        return this.checkResponse(response, expectedStatus, description);
    }
    
    // Array and Numeric Assertions
    
    assertArrayLength(data, arrayField, expectedLength, description = 'Array length') {
        try {
            const arr = data[arrayField];
            const actualLength = Array.isArray(arr) ? arr.length : 0;
            
            if (actualLength === expectedLength) {
                this.baseTest.printSuccess(`${description}: expected length ${expectedLength}, got ${actualLength}`);
                return true;
            } else {
                this.baseTest.printError(`${description}: expected length ${expectedLength}, got ${actualLength}`);
                return false;
            }
        } catch (error) {
            this.baseTest.printError(`${description}: expected length ${expectedLength}, got 0`);
            return false;
        }
    }
    
    assertGreaterThan(actual, threshold, description = 'Numeric comparison') {
        if (parseFloat(actual) > parseFloat(threshold)) {
            this.baseTest.printSuccess(`${description}: ${actual} > ${threshold}`);
            return true;
        } else {
            this.baseTest.printError(`${description}: ${actual} <= ${threshold}`);
            return false;
        }
    }
    
    assertLessThan(actual, threshold, description = 'Numeric comparison') {
        if (parseFloat(actual) < parseFloat(threshold)) {
            this.baseTest.printSuccess(`${description}: ${actual} < ${threshold}`);
            return true;
        } else {
            this.baseTest.printError(`${description}: ${actual} >= ${threshold}`);
            return false;
        }
    }
}

module.exports = Assertions;