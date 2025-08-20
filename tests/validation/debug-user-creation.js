#!/usr/bin/env node

/**
 * Debug script for user creation validation failure
 * Reproduces the exact API call from the validation test to see why it's failing
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const { URL } = require('url');

class UserCreationDebugger {
    constructor() {
        this.apiBase = process.env.API_BASE || 'http://localhost:8080';
        this.apiUrl = `${this.apiBase}/api/v1`;
        this.cookies = new Map();
        
        // Load cookies from the cookie file
        this.loadCookies();
    }

    /**
     * Load cookies from the cookie file using the same logic as validation tests
     */
    loadCookies() {
        const possiblePaths = [
            './test_cookies.txt',
            '../test_cookies.txt',
            '/tmp/cookies.txt'
        ];
        
        let cookieFile = null;
        for (const path of possiblePaths) {
            if (fs.existsSync(path)) {
                cookieFile = path;
                break;
            }
        }
        
        if (!cookieFile) {
            console.error('❌ Cookie file not found. Tried:', possiblePaths);
            return;
        }

        try {
            const content = fs.readFileSync(cookieFile, 'utf8').trim();
            if (content) {
                console.log(`📂 Loading cookies from: ${cookieFile}`);
                
                // Parse Netscape cookie format (same logic as validation test)
                const lines = content.split('\n');
                for (const line of lines) {
                    // Skip only true comment lines (# followed by space or at start of file)
                    // #HttpOnly_ lines are NOT comments but cookie data
                    if (line.match(/^#\s/) || line === '#' || !line.trim()) {
                        continue;
                    }
                    const parts = line.split('\t');
                    if (parts.length >= 7) {
                        const domain = parts[0];
                        const name = parts[5];
                        const value = parts[6];
                        this.cookies.set(name, value);
                        console.log(`🍪 Loaded cookie: ${name} (domain: ${domain})`);
                    }
                }
            }
            
            if (this.cookies.size === 0) {
                console.error('⚠️ Warning: No cookies loaded from file');
            } else {
                console.log(`✅ Loaded ${this.cookies.size} cookie(s)`);
            }
        } catch (e) {
            console.error(`❌ Failed to load cookies: ${e.message}`);
        }
    }

    /**
     * Make an HTTP request and return detailed response information
     */
    async apiCall(method, endpoint, data = null) {
        return new Promise((resolve, reject) => {
            const url = new URL(`${this.apiUrl}${endpoint}`);
            const isHttps = url.protocol === 'https:';
            const client = isHttps ? https : http;
            
            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: method.toUpperCase(),
                headers: {
                    'User-Agent': 'Babbel-UserCreation-Debug/1.0',
                    'Content-Type': 'application/json'
                }
            };

            // Add cookies
            if (this.cookies.size > 0) {
                const cookieString = Array.from(this.cookies.entries())
                    .map(([name, value]) => `${name}=${value}`)
                    .join('; ');
                options.headers['Cookie'] = cookieString;
                console.log(`🍪 Sending cookies: ${cookieString.substring(0, 100)}...`);
            } else {
                console.log('⚠️ No cookies to send');
            }

            let requestData = null;
            if (data) {
                requestData = JSON.stringify(data);
                options.headers['Content-Length'] = Buffer.byteLength(requestData);
            }

            console.log('\n📤 REQUEST DETAILS:');
            console.log(`Method: ${options.method}`);
            console.log(`URL: ${this.apiUrl}${endpoint}`);
            console.log('Headers:', JSON.stringify(options.headers, null, 2));
            if (requestData) {
                console.log('Body:', requestData);
            }

            const req = client.request(options, (res) => {
                let responseBody = '';
                
                res.on('data', (chunk) => {
                    responseBody += chunk;
                });
                
                res.on('end', () => {
                    console.log('\n📥 RESPONSE DETAILS:');
                    console.log(`Status Code: ${res.statusCode}`);
                    console.log('Headers:', JSON.stringify(res.headers, null, 2));
                    console.log('Raw Body:', responseBody);
                    
                    // Try to parse JSON response
                    let responseData;
                    try {
                        responseData = JSON.parse(responseBody);
                        console.log('Parsed JSON:', JSON.stringify(responseData, null, 2));
                    } catch (e) {
                        console.log('⚠️ Response is not JSON');
                        responseData = { raw_text: responseBody };
                    }
                    
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        data: responseData,
                        rawBody: responseBody
                    });
                });
            });
            
            req.on('error', (error) => {
                console.error(`❌ Request failed: ${error.message}`);
                reject(error);
            });
            
            if (requestData) {
                req.write(requestData);
            }
            
            req.end();
        });
    }

    /**
     * Test the exact user creation call from the validation test
     */
    async debugUserCreation() {
        console.log('🔍 DEBUGGING USER CREATION VALIDATION FAILURE');
        console.log('='.repeat(60));

        // This is the exact same data from the validation test (line 569)
        const userData = {
            username: "valid_user",
            full_name: "Test User", 
            password: "validpassword"
        };

        console.log('\n🎯 Testing user creation with data:', JSON.stringify(userData, null, 2));

        try {
            const response = await this.apiCall('POST', '/users', userData);
            
            console.log('\n📊 ANALYSIS:');
            console.log(`Expected: HTTP 201 Created`);
            console.log(`Actual: HTTP ${response.statusCode}`);
            
            if (response.statusCode === 422) {
                console.log('\n❌ VALIDATION ERROR DETAILS:');
                if (response.data.errors) {
                    console.log('Validation errors:', JSON.stringify(response.data.errors, null, 2));
                } else if (response.data.error) {
                    console.log('Error message:', response.data.error);
                } else {
                    console.log('Full response:', JSON.stringify(response.data, null, 2));
                }
                
                // Check for common validation issues
                this.analyzeValidationErrors(response.data);
            } else if (response.statusCode === 201) {
                console.log('✅ User creation succeeded!');
                console.log('Created user ID:', response.data.id);
            } else {
                console.log(`❓ Unexpected status code: ${response.statusCode}`);
                console.log('Response:', JSON.stringify(response.data, null, 2));
            }

        } catch (error) {
            console.error(`💥 Request failed: ${error.message}`);
        }
    }

    /**
     * Analyze validation errors to identify the issue
     */
    analyzeValidationErrors(responseData) {
        console.log('\n🔍 VALIDATION ERROR ANALYSIS:');
        
        const errorStr = JSON.stringify(responseData).toLowerCase();
        
        if (errorStr.includes('username')) {
            console.log('❌ Username validation issue detected');
        }
        if (errorStr.includes('password')) {
            console.log('❌ Password validation issue detected');
        }
        if (errorStr.includes('email')) {
            console.log('❌ Email validation issue detected');
        }
        if (errorStr.includes('role')) {
            console.log('❌ Role validation issue detected');
        }
        if (errorStr.includes('full_name')) {
            console.log('❌ Full name validation issue detected');
        }
        if (errorStr.includes('duplicate') || errorStr.includes('already exists')) {
            console.log('❌ Duplicate constraint violation detected');
        }
        if (errorStr.includes('required')) {
            console.log('❌ Required field missing');
        }
    }

    /**
     * Get existing users to check for conflicts
     */
    async checkExistingUsers() {
        console.log('\n👥 CHECKING EXISTING USERS FOR CONFLICTS');
        console.log('-'.repeat(50));

        try {
            const response = await this.apiCall('GET', '/users');
            
            if (response.statusCode === 200) {
                const users = response.data.data || response.data; // Handle paginated response
                console.log(`Found ${users.length} existing users:`);
                
                let foundConflict = false;
                users.forEach(user => {
                    console.log(`- ID: ${user.id}, Username: ${user.username}, Email: ${user.email || 'N/A'}`);
                    
                    if (user.username === 'valid_user') {
                        console.log('  ❌ CONFLICT: Username "valid_user" already exists!');
                        foundConflict = true;
                    }
                });
                
                if (!foundConflict) {
                    console.log('✅ No username conflicts found');
                }
                return true; // Success
            } else {
                console.log(`❌ Failed to get users: HTTP ${response.statusCode}`);
                console.log('Response:', JSON.stringify(response.data, null, 2));
                return false; // Failed
            }
        } catch (error) {
            console.error(`💥 Failed to check existing users: ${error.message}`);
            return false; // Failed
        }
    }

    /**
     * Authenticate with fresh credentials
     */
    async authenticateWithFreshLogin() {
        console.log('\n🔐 ATTEMPTING FRESH AUTHENTICATION');
        console.log('-'.repeat(50));

        const loginData = {
            username: "admin",
            password: "admin"
        };

        try {
            const response = await this.apiCall('POST', '/sessions', loginData);
            
            if (response.statusCode === 201) {
                console.log('✅ Fresh authentication successful');
                
                // Extract and store new session cookie from response headers
                const setCookieHeader = response.headers['set-cookie'];
                if (setCookieHeader) {
                    for (const cookie of setCookieHeader) {
                        if (cookie.includes('babbel_session=')) {
                            const sessionValue = cookie.split('babbel_session=')[1].split(';')[0];
                            this.cookies.set('babbel_session', sessionValue);
                            console.log(`🍪 Updated session cookie: ${sessionValue.substring(0, 20)}...`);
                        }
                    }
                }
                return true;
            } else {
                console.log(`❌ Fresh authentication failed: HTTP ${response.statusCode}`);
                console.log('Response:', JSON.stringify(response.data, null, 2));
                return false;
            }
        } catch (error) {
            console.error(`💥 Authentication request failed: ${error.message}`);
            return false;
        }
    }

    /**
     * Run complete debug analysis
     */
    async run() {
        // First try with existing cookie
        console.log('👤 Testing with existing cookie...');
        const existingUsersResponse = await this.checkExistingUsers();
        
        // If authentication failed, get fresh authentication
        if (!existingUsersResponse) {
            console.log('🔄 Existing session failed, trying fresh authentication...');
            const authSuccess = await this.authenticateWithFreshLogin();
            if (!authSuccess) {
                console.log('❌ Authentication failed, cannot proceed with user creation test');
                return;
            }
            
            // Try again with fresh auth
            await this.checkExistingUsers();
        }
        
        // Now test user creation
        await this.debugUserCreation();
        
        console.log('\n🏁 DEBUG COMPLETE');
        console.log('='.repeat(60));
    }
}

/**
 * Main execution
 */
async function main() {
    const userDebugger = new UserCreationDebugger();
    await userDebugger.run();
}

if (require.main === module) {
    main().catch(console.error);
}