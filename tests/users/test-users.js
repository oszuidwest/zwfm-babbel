/**
 * Babbel Users Tests - Node.js
 * Test user management functionality
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class UsersTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Global variables for tracking created resources
        this.createdUserIds = [];
        this.createdUsernames = [];
        this.lastCreatedUserId = null;
        this.lastCreatedUsername = null;
    }
    
    /**
     * Helper function to create a user
     */
    async createUser(username, fullName, password, email = '', role = 'viewer', notes = '') {
        // Make username unique
        const timestamp = Date.now();
        const uniqueUsername = `${username}_${timestamp}_${process.pid}`;
        
        const userData = {
            username: uniqueUsername,
            full_name: fullName,
            password: password,
            role: role
        };
        
        if (email) {
            userData.email = email;
        }
        
        if (notes) {
            userData.notes = notes;
        }
        
        const response = await this.apiCall('POST', '/users', userData);
        
        if (response.status === 201) {
            const userId = this.parseJsonField(response.data, 'id');
            if (userId) {
                this.createdUserIds.push(userId);
                this.createdUsernames.push(uniqueUsername);
                this.lastCreatedUserId = userId;
                this.lastCreatedUsername = uniqueUsername;
                return userId;
            }
        }
        
        return null;
    }
    
    /**
     * Helper function to get user details
     */
    async getUser(userId) {
        const response = await this.apiCall('GET', `/users/${userId}`);
        
        if (response.status === 200) {
            return response.data;
        }
        
        return null;
    }
    
    /**
     * Helper function to update user status (suspend/restore)
     */
    async updateUserStatus(userId, suspended) {
        const userData = { suspended: suspended };
        const response = await this.apiCall('PUT', `/users/${userId}`, userData);
        return response.status === 200;
    }
    
    /**
     * Test user creation
     */
    async testCreateUser() {
        this.printSection('Testing User Creation');
        
        this.printInfo('Creating a new user');
        
        const timestamp = Date.now();
        const userId = await this.createUser('testuser', 'Test User', 'password123', `test${timestamp}@example.com`, 'viewer', '');
        
        if (userId && parseInt(userId) > 0) {
            this.printSuccess(`User created with ID: ${userId}`);
            return true;
        } else {
            this.printError('Failed to create user');
            return false;
        }
    }
    
    /**
     * Test user creation with minimal data
     */
    async testCreateUserMinimal() {
        this.printSection('Testing User Creation with Minimal Data');
        
        this.printInfo('Creating user with minimal required data');
        
        const userId = await this.createUser('minimaluser', 'Minimal User', 'password456', '', 'editor');
        
        if (userId && parseInt(userId) > 0) {
            this.printSuccess(`Minimal user created with ID: ${userId}`);
            return true;
        } else {
            this.printError('Failed to create minimal user');
            return false;
        }
    }
    
    /**
     * Test user creation with different roles
     */
    async testCreateUsersDifferentRoles() {
        this.printSection('Testing User Creation with Different Roles');
        
        this.printInfo('Creating users with different roles');
        
        const timestamp = Date.now();
        const adminId = await this.createUser('adminuser', 'Admin User', 'adminpass123', `admin${timestamp}@example.com`, 'admin');
        const editorId = await this.createUser('editoruser', 'Editor User', 'editorpass123', `editor${timestamp}@example.com`, 'editor');
        const viewerId = await this.createUser('vieweruser', 'Viewer User', 'viewerpass123', `viewer${timestamp}@example.com`, 'viewer');
        
        let success = 0;
        
        if (adminId && parseInt(adminId) > 0) {
            this.printSuccess(`Admin user created with ID: ${adminId}`);
            success++;
        } else {
            this.printError('Failed to create admin user');
        }
        
        if (editorId && parseInt(editorId) > 0) {
            this.printSuccess(`Editor user created with ID: ${editorId}`);
            success++;
        } else {
            this.printError('Failed to create editor user');
        }
        
        if (viewerId && parseInt(viewerId) > 0) {
            this.printSuccess(`Viewer user created with ID: ${viewerId}`);
            success++;
        } else {
            this.printError('Failed to create viewer user');
        }
        
        if (success === 3) {
            this.printSuccess('All users with different roles created successfully');
            return true;
        } else {
            this.printError(`Only ${success}/3 users created successfully`);
            return false;
        }
    }
    
    /**
     * Test user creation validation errors
     */
    async testCreateUserValidationErrors() {
        this.printSection('Testing User Creation Validation Errors');
        
        // Test missing username
        this.printInfo('Testing user creation without username...');
        let response = await this.apiCall('POST', '/users', {
            full_name: 'No Username User',
            password: 'password123',
            role: 'viewer'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Missing username correctly rejected');
        } else {
            this.printError(`Missing username not rejected (HTTP: ${response.status})`);
            return false;
        }
        
        // Test missing password
        this.printInfo('Testing user creation without password...');
        response = await this.apiCall('POST', '/users', {
            username: 'nopassuser',
            full_name: 'No Password User',
            role: 'viewer'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Missing password correctly rejected');
        } else {
            this.printError(`Missing password not rejected (HTTP: ${response.status})`);
            return false;
        }
        
        // Test invalid role
        this.printInfo('Testing user creation with invalid role...');
        response = await this.apiCall('POST', '/users', {
            username: 'invalidroleuser',
            full_name: 'Invalid Role User',
            password: 'password123',
            role: 'invalid_role'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Invalid role correctly rejected');
        } else {
            this.printError(`Invalid role not rejected (HTTP: ${response.status})`);
            return false;
        }
        
        // Test short password
        this.printInfo('Testing user creation with short password...');
        response = await this.apiCall('POST', '/users', {
            username: 'shortpassuser',
            full_name: 'Short Password User',
            password: '123',
            role: 'viewer'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Short password correctly rejected');
        } else {
            this.printWarning(`Short password not rejected (HTTP: ${response.status})`);
        }
        
        return true;
    }
    
    /**
     * Test duplicate user constraints
     */
    async testDuplicateUserConstraints() {
        this.printSection('Testing Duplicate User Constraints');
        
        // Create a user first
        const timestamp = Date.now();
        const username = `duplicatetest_${timestamp}`;
        const email = `duplicate${timestamp}@example.com`;
        
        this.printInfo('Creating first user...');
        const firstUserId = await this.createUser(username.replace(`_${timestamp}`, ''), 'First User', 'password123', email, 'viewer');
        
        if (!firstUserId) {
            this.printError('Failed to create first user for duplicate test');
            return false;
        }
        
        this.printSuccess(`First user created with ID: ${firstUserId}`);
        
        // Try to create a user with the same username (with timestamp)
        this.printInfo('Testing duplicate username constraint...');
        const duplicateUsernameResponse = await this.apiCall('POST', '/users', {
            username: this.lastCreatedUsername, // Use the exact username that was created
            full_name: 'Duplicate Username User',
            password: 'password456',
            role: 'editor'
        });
        
        if (duplicateUsernameResponse.status === 409 || duplicateUsernameResponse.status === 422) {
            this.printSuccess('Duplicate username correctly rejected');
        } else {
            this.printError(`Duplicate username not rejected (HTTP: ${duplicateUsernameResponse.status})`);
            return false;
        }
        
        // Try to create a user with the same email (if emails are enforced to be unique)
        if (email) {
            this.printInfo('Testing duplicate email constraint...');
            const duplicateEmailResponse = await this.apiCall('POST', '/users', {
                username: `differentuser_${timestamp}`,
                full_name: 'Duplicate Email User',
                password: 'password789',
                email: email,
                role: 'viewer'
            });
            
            if (duplicateEmailResponse.status === 409 || duplicateEmailResponse.status === 422) {
                this.printSuccess('Duplicate email correctly rejected');
            } else {
                this.printWarning(`Duplicate email not rejected (HTTP: ${duplicateEmailResponse.status}) - may not be enforced`);
            }
        }
        
        return true;
    }
    
    /**
     * Test user listing
     */
    async testListUsers() {
        this.printSection('Testing User Listing');
        
        this.printInfo('Testing basic user listing...');
        const response = await this.apiCall('GET', '/users');
        
        if (this.assertions.checkResponse(response, 200, 'List users')) {
            // Check for data array
            if (response.data.data && Array.isArray(response.data.data)) {
                const count = response.data.data.length;
                this.printSuccess(`User listing returned ${count} users`);
                
                // Check pagination info
                if (response.data.pagination) {
                    const pagination = response.data.pagination;
                    this.printInfo(`Pagination: total=${pagination.total}, limit=${pagination.limit}, offset=${pagination.offset}`);
                }
                
                // Verify user data structure
                if (count > 0) {
                    const firstUser = response.data.data[0];
                    const requiredFields = ['id', 'username', 'full_name', 'role'];
                    const missingFields = requiredFields.filter(field => !firstUser.hasOwnProperty(field));
                    
                    if (missingFields.length === 0) {
                        this.printSuccess('User data structure contains required fields');
                    } else {
                        this.printError(`Missing user fields: ${missingFields.join(', ')}`);
                        return false;
                    }
                }
            } else {
                this.printError('User listing response missing data array');
                return false;
            }
        } else {
            return false;
        }
        
        // Test pagination
        this.printInfo('Testing user pagination...');
        const paginationResponse = await this.apiCall('GET', '/users?limit=2&offset=0');
        
        if (this.assertions.checkResponse(paginationResponse, 200, 'Paginated user listing')) {
            const count = paginationResponse.data.data ? paginationResponse.data.data.length : 0;
            if (count <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${count} users)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${count} users)`);
                return false;
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test user listing with role filter
     */
    async testListUsersRoleFilter() {
        this.printSection('Testing User Listing with Role Filter');
        
        // Test filtering by admin role
        this.printInfo('Testing filter by admin role...');
        const adminResponse = await this.apiCall('GET', '/users?role=admin');
        
        if (this.assertions.checkResponse(adminResponse, 200, 'Filter users by admin role')) {
            this.printSuccess('Admin role filter works');
        } else {
            return false;
        }
        
        // Test filtering by editor role
        this.printInfo('Testing filter by editor role...');
        const editorResponse = await this.apiCall('GET', '/users?role=editor');
        
        if (this.assertions.checkResponse(editorResponse, 200, 'Filter users by editor role')) {
            this.printSuccess('Editor role filter works');
        } else {
            return false;
        }
        
        // Test filtering by viewer role
        this.printInfo('Testing filter by viewer role...');
        const viewerResponse = await this.apiCall('GET', '/users?role=viewer');
        
        if (this.assertions.checkResponse(viewerResponse, 200, 'Filter users by viewer role')) {
            this.printSuccess('Viewer role filter works');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test getting individual user
     */
    async testGetUser() {
        this.printSection('Testing Get Individual User');
        
        // Create a user to test with
        this.printInfo('Creating user for get test...');
        const userId = await this.createUser('gettest', 'Get Test User', 'password123', 'gettest@example.com', 'editor', 'Test notes');
        
        if (!userId) {
            this.printError('Failed to create user for get test');
            return false;
        }
        
        // Test getting the user
        this.printInfo(`Testing get user by ID: ${userId}...`);
        const response = await this.apiCall('GET', `/users/${userId}`);
        
        if (this.assertions.checkResponse(response, 200, 'Get user by ID')) {
            const user = response.data;
            
            // Verify user data
            if (user.id == userId && user.full_name === 'Get Test User' && user.role === 'editor') {
                this.printSuccess('Retrieved user data is correct');
            } else {
                this.printError('Retrieved user data is incorrect');
                return false;
            }
            
            // Check that password is not included in response
            if (!user.hasOwnProperty('password')) {
                this.printSuccess('Password correctly excluded from user data');
            } else {
                this.printError('Password included in user data (security issue)');
                return false;
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test getting non-existent user
     */
    async testGetNonexistentUser() {
        this.printSection('Testing Get Non-existent User');
        
        this.printInfo('Testing get non-existent user...');
        const response = await this.apiCall('GET', '/users/99999');
        
        if (response.status === 404) {
            this.printSuccess('Non-existent user correctly returns 404');
        } else {
            this.printError(`Non-existent user returned unexpected status: ${response.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test updating user
     */
    async testUpdateUser() {
        this.printSection('Testing User Update');
        
        // Create a user to update
        this.printInfo('Creating user for update test...');
        const userId = await this.createUser('updatetest', 'Update Test User', 'password123', 'updatetest@example.com', 'viewer');
        
        if (!userId) {
            this.printError('Failed to create user for update test');
            return false;
        }
        
        // Test updating full name
        this.printInfo('Testing update full name...');
        let response = await this.apiCall('PUT', `/users/${userId}`, {
            full_name: 'Updated Full Name'
        });
        
        if (this.assertions.checkResponse(response, 200, 'Update user full name')) {
            // Verify the update
            const user = await this.getUser(userId);
            if (user && user.full_name === 'Updated Full Name') {
                this.printSuccess('Full name updated successfully');
            } else {
                this.printError('Full name not updated correctly');
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating role
        this.printInfo('Testing update role...');
        response = await this.apiCall('PUT', `/users/${userId}`, {
            role: 'editor'
        });
        
        if (this.assertions.checkResponse(response, 200, 'Update user role')) {
            // Verify the update
            const user = await this.getUser(userId);
            if (user && user.role === 'editor') {
                this.printSuccess('Role updated successfully');
            } else {
                this.printError('Role not updated correctly');
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating email
        this.printInfo('Testing update email...');
        response = await this.apiCall('PUT', `/users/${userId}`, {
            email: 'updated@example.com'
        });
        
        if (this.assertions.checkResponse(response, 200, 'Update user email')) {
            this.printSuccess('Email updated successfully');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test suspending user
     */
    async testSuspendUser() {
        this.printSection('Testing User Suspension');
        
        // Create a user to suspend
        this.printInfo('Creating user for suspension test...');
        const userId = await this.createUser('suspendtest', 'Suspend Test User', 'password123', 'suspendtest@example.com', 'editor');
        
        if (!userId) {
            this.printError('Failed to create user for suspension test');
            return false;
        }
        
        // Test suspending the user
        this.printInfo('Testing user suspension...');
        const success = await this.updateUserStatus(userId, true);
        
        if (success) {
            // Verify the user is suspended
            const user = await this.getUser(userId);
            if (user && user.suspended === true) {
                this.printSuccess('User suspended successfully');
            } else {
                this.printError('User suspension not reflected in user data');
                return false;
            }
        } else {
            this.printError('Failed to suspend user');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test restoring suspended user
     */
    async testRestoreUser() {
        this.printSection('Testing User Restoration');
        
        // Create and suspend a user first
        this.printInfo('Creating and suspending user for restoration test...');
        const userId = await this.createUser('restoretest', 'Restore Test User', 'password123', 'restoretest@example.com', 'editor');
        
        if (!userId) {
            this.printError('Failed to create user for restoration test');
            return false;
        }
        
        // Suspend the user first
        const suspendSuccess = await this.updateUserStatus(userId, true);
        if (!suspendSuccess) {
            this.printError('Failed to suspend user for restoration test');
            return false;
        }
        
        // Test restoring the user
        this.printInfo('Testing user restoration...');
        const restoreSuccess = await this.updateUserStatus(userId, false);
        
        if (restoreSuccess) {
            // Verify the user is restored
            const user = await this.getUser(userId);
            if (user && (user.suspended === false || user.suspended === null || user.suspended === undefined)) {
                this.printSuccess('User restored successfully');
            } else {
                this.printError('User restoration not reflected in user data');
                return false;
            }
        } else {
            this.printError('Failed to restore user');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test user field validation
     */
    async testUserFieldValidation() {
        this.printSection('Testing User Field Validation');
        
        // Create a user to test field validation on
        this.printInfo('Creating user for field validation test...');
        const userId = await this.createUser('fieldtest', 'Field Test User', 'password123', 'fieldtest@example.com', 'viewer');
        
        if (!userId) {
            this.printError('Failed to create user for field validation test');
            return false;
        }
        
        // Test invalid email format
        this.printInfo('Testing invalid email format...');
        let response = await this.apiCall('PUT', `/users/${userId}`, {
            email: 'invalid-email-format'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Invalid email format correctly rejected');
        } else {
            this.printWarning(`Invalid email format not rejected (HTTP: ${response.status})`);
        }
        
        // Test invalid role
        this.printInfo('Testing invalid role update...');
        response = await this.apiCall('PUT', `/users/${userId}`, {
            role: 'invalid_role_name'
        });
        
        if (response.status === 422 || response.status === 400) {
            this.printSuccess('Invalid role correctly rejected');
        } else {
            this.printError(`Invalid role not rejected (HTTP: ${response.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test deleting user
     */
    async testDeleteUser() {
        this.printSection('Testing User Deletion');
        
        // Create a user to delete
        this.printInfo('Creating user for deletion test...');
        const userId = await this.createUser('deletetest', 'Delete Test User', 'password123', 'deletetest@example.com', 'viewer');
        
        if (!userId) {
            this.printError('Failed to create user for deletion test');
            return false;
        }
        
        // Test deleting the user
        this.printInfo('Testing user deletion...');
        const response = await this.apiCall('DELETE', `/users/${userId}`);
        
        if (this.assertions.checkResponse(response, 204, 'Delete user')) {
            this.printSuccess('User deleted successfully');
            
            // Verify the user is deleted
            const getResponse = await this.apiCall('GET', `/users/${userId}`);
            if (getResponse.status === 404) {
                this.printSuccess('Deleted user correctly returns 404');
                // Remove from our tracking list since it's deleted
                const index = this.createdUserIds.indexOf(userId);
                if (index > -1) {
                    this.createdUserIds.splice(index, 1);
                }
            } else {
                this.printError(`Deleted user still accessible (HTTP: ${getResponse.status})`);
                return false;
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test deleting non-existent user
     */
    async testDeleteNonexistentUser() {
        this.printSection('Testing Delete Non-existent User');
        
        this.printInfo('Testing deletion of non-existent user...');
        const response = await this.apiCall('DELETE', '/users/99999');
        
        if (response.status === 404) {
            this.printSuccess('Non-existent user deletion correctly returns 404');
        } else {
            this.printError(`Non-existent user deletion returned unexpected code: ${response.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test last admin protection
     */
    async testLastAdminProtection() {
        this.printSection('Testing Last Admin Protection');
        
        // First, get all admin users
        this.printInfo('Getting current admin users...');
        const adminsResponse = await this.apiCall('GET', '/users?role=admin');
        
        if (!this.assertions.checkResponse(adminsResponse, 200, 'Get admin users')) {
            return false;
        }
        
        const adminUsers = adminsResponse.data.data || [];
        this.printInfo(`Found ${adminUsers.length} admin users`);
        
        if (adminUsers.length === 0) {
            this.printWarning('No admin users found, cannot test last admin protection');
            return true;
        }
        
        // If there's only one admin, test protection
        if (adminUsers.length === 1) {
            const lastAdmin = adminUsers[0];
            
            // Test deleting the last admin
            this.printInfo(`Testing deletion of last admin (ID: ${lastAdmin.id})...`);
            const deleteResponse = await this.apiCall('DELETE', `/users/${lastAdmin.id}`);
            
            if (deleteResponse.status === 403 || deleteResponse.status === 422) {
                this.printSuccess('Last admin deletion correctly rejected');
            } else {
                this.printError(`Last admin deletion not rejected (HTTP: ${deleteResponse.status})`);
                return false;
            }
            
            // Test changing the last admin's role
            this.printInfo('Testing role change of last admin...');
            const roleChangeResponse = await this.apiCall('PUT', `/users/${lastAdmin.id}`, {
                role: 'editor'
            });
            
            if (roleChangeResponse.status === 403 || roleChangeResponse.status === 422) {
                this.printSuccess('Last admin role change correctly rejected');
            } else {
                this.printWarning(`Last admin role change not rejected (HTTP: ${roleChangeResponse.status})`);
            }
        } else {
            // Create a test scenario with multiple admins
            this.printInfo('Multiple admins exist, creating test scenario...');
            
            // Create a new admin user
            const newAdminId = await this.createUser('testadmin', 'Test Admin User', 'password123', 'testadmin@example.com', 'admin');
            
            if (newAdminId) {
                this.printSuccess('Created additional admin for testing');
                
                // Test that we can delete this admin (since it's not the last one)
                const deleteResponse = await this.apiCall('DELETE', `/users/${newAdminId}`);
                
                if (deleteResponse.status === 204) {
                    this.printSuccess('Non-last admin deletion works correctly');
                    // Remove from tracking since it's deleted
                    const index = this.createdUserIds.indexOf(newAdminId);
                    if (index > -1) {
                        this.createdUserIds.splice(index, 1);
                    }
                } else {
                    this.printWarning(`Non-last admin deletion returned: ${deleteResponse.status}`);
                }
            }
        }
        
        return true;
    }
    
    /**
     * Test password security
     */
    async testPasswordSecurity() {
        this.printSection('Testing Password Security');
        
        // Test that passwords are not returned in API responses
        this.printInfo('Testing password exclusion from API responses...');
        
        // Create a user
        const userId = await this.createUser('passwordtest', 'Password Test User', 'secretpassword123', 'passwordtest@example.com', 'viewer');
        
        if (!userId) {
            this.printError('Failed to create user for password security test');
            return false;
        }
        
        // Get the user and check that password is not included
        const user = await this.getUser(userId);
        if (user) {
            if (!user.hasOwnProperty('password')) {
                this.printSuccess('Password correctly excluded from user data');
            } else {
                this.printError('Password included in user data (security vulnerability)');
                return false;
            }
        } else {
            this.printError('Failed to retrieve user for password security test');
            return false;
        }
        
        // Test that password updates work but don't return the password
        this.printInfo('Testing password update...');
        const updateResponse = await this.apiCall('PUT', `/users/${userId}`, {
            password: 'newpassword456'
        });
        
        if (this.assertions.checkResponse(updateResponse, 200, 'Update password')) {
            // Check that the response doesn't include the password
            if (!updateResponse.data.hasOwnProperty('password')) {
                this.printSuccess('Password update response correctly excludes password');
            } else {
                this.printError('Password update response includes password (security issue)');
                return false;
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test authentication fields
     */
    async testAuthenticationFields() {
        this.printSection('Testing Authentication Fields');
        
        // Create a user to test authentication fields
        this.printInfo('Creating user for authentication fields test...');
        const userId = await this.createUser('authtest', 'Auth Test User', 'password123', 'authtest@example.com', 'editor');
        
        if (!userId) {
            this.printError('Failed to create user for authentication fields test');
            return false;
        }
        
        // Get the user and check authentication-related fields
        const user = await this.getUser(userId);
        if (user) {
            // Check for expected authentication fields
            const authFields = ['created_at', 'updated_at'];
            const presentFields = authFields.filter(field => user.hasOwnProperty(field));
            
            if (presentFields.length > 0) {
                this.printSuccess(`Authentication timestamp fields present: ${presentFields.join(', ')}`);
            } else {
                this.printWarning('No authentication timestamp fields found');
            }
            
            // Check that sensitive fields are not present
            const sensitiveFields = ['password', 'password_hash'];
            const foundSensitive = sensitiveFields.filter(field => user.hasOwnProperty(field));
            
            if (foundSensitive.length === 0) {
                this.printSuccess('No sensitive authentication fields exposed');
            } else {
                this.printError(`Sensitive fields exposed: ${foundSensitive.join(', ')}`);
                return false;
            }
        } else {
            this.printError('Failed to retrieve user for authentication fields test');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test user validation
     */
    async testUserValidation() {
        this.printSection('Testing User Validation');
        
        // Test invalid user data
        const invalidData = {
            username: '',
            password: '123',
            role: 'invalid_role'
        };
        
        const response = await this.apiCall('POST', '/users', invalidData);
        
        if (this.assertions.assertHttpError(response.status, 'Invalid user data')) {
            this.printSuccess('User validation correctly rejected invalid data');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up user tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up user tests...');
        
        // Delete all created users
        for (const userId of this.createdUserIds) {
            try {
                await this.apiCall('DELETE', `/users/${userId}`);
                this.printInfo(`Cleaned up user: ${userId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
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
        this.printHeader('User Tests');
        
        await this.setup();
        
        const tests = [
            'testCreateUser',
            'testCreateUserMinimal',
            'testCreateUsersDifferentRoles',
            'testCreateUserValidationErrors',
            'testDuplicateUserConstraints',
            'testListUsers',
            'testListUsersRoleFilter',
            'testGetUser',
            'testGetNonexistentUser',
            'testUpdateUser',
            'testSuspendUser',
            'testRestoreUser',
            'testUserFieldValidation',
            'testDeleteUser',
            'testDeleteNonexistentUser',
            'testLastAdminProtection',
            'testPasswordSecurity',
            'testAuthenticationFields'
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
            this.printSuccess('All user tests passed!');
            return true;
        } else {
            this.printError(`${failed} user tests failed`);
            return false;
        }
    }
}

module.exports = UsersTests;
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
