#!/usr/bin/env python3
"""
Babbel Validation Tests - Python Implementation

Comprehensive validation testing for all API endpoints with proper JSON handling.
Tests field validation, data types, boundaries, business rules, and input sanitization.

This script replaces the bash implementation to solve JSON parsing issues when
using colons as delimiters in test data that also contains colons.
"""

import sys
import os
import json
import tempfile
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import uuid
import urllib.request
import urllib.parse
import urllib.error
from http.cookiejar import CookieJar

# Try to import requests, fall back to urllib if not available
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class Colors:
    """Terminal color codes for output formatting"""
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


class TestResult(Enum):
    """Test result types"""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class TestCase:
    """Represents a single test case"""
    name: str
    data: Dict[str, Any]
    expected_status: int
    description: str
    endpoint: str = ""
    method: str = "POST"


class ValidationTester:
    """Main class for running validation tests"""
    
    def __init__(self):
        self.api_base = os.getenv('API_BASE', 'http://localhost:8080')
        self.api_url = f"{self.api_base}/api/v1"
        self.cookie_file = './test_cookies.txt'
        self.session = requests.Session()
        
        # Test counters
        self.tests_passed = 0
        self.tests_failed = 0
        
        # Created resources for cleanup
        self.created_station_ids = []
        self.created_voice_ids = []
        self.created_story_ids = []
        self.created_user_ids = []
        self.created_station_voice_ids = []
        
        # Load cookies if available
        self._load_cookies()
    
    def _load_cookies(self):
        """Load cookies from the cookie file"""
        try:
            if os.path.exists(self.cookie_file):
                with open(self.cookie_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Parse Netscape cookie format
                        for line in content.split('\n'):
                            if line.startswith('#') or not line.strip():
                                continue
                            parts = line.split('\t')
                            if len(parts) >= 7:
                                domain = parts[0]
                                name = parts[5]
                                value = parts[6]
                                self.session.cookies.set(name, value, domain=domain)
        except Exception as e:
            self.print_error(f"Failed to load cookies: {e}")
    
    def print_header(self, text: str):
        """Print a header with formatting"""
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}{'=' * 60}{Colors.NC}", file=sys.stderr)
        print(f"{Colors.MAGENTA}{Colors.BOLD}  {text}{Colors.NC}", file=sys.stderr)
        print(f"{Colors.MAGENTA}{Colors.BOLD}{'=' * 60}{Colors.NC}\n", file=sys.stderr)
    
    def print_section(self, text: str):
        """Print a section header"""
        print(f"\n{Colors.CYAN}━━━ {text} ━━━{Colors.NC}", file=sys.stderr)
    
    def print_success(self, text: str):
        """Print success message and increment counter"""
        print(f"{Colors.GREEN}✓ {text}{Colors.NC}", file=sys.stderr)
        self.tests_passed += 1
    
    def print_error(self, text: str):
        """Print error message and increment counter"""
        print(f"{Colors.RED}✗ {text}{Colors.NC}", file=sys.stderr)
        self.tests_failed += 1
    
    def print_info(self, text: str):
        """Print info message"""
        print(f"{Colors.YELLOW}ℹ {text}{Colors.NC}", file=sys.stderr)
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠ {text}{Colors.NC}", file=sys.stderr)
    
    def print_summary(self):
        """Print test summary"""
        total = self.tests_passed + self.tests_failed
        print(f"\n{Colors.BOLD}Test Summary:{Colors.NC}", file=sys.stderr)
        print(f"{Colors.GREEN}✓ Passed: {self.tests_passed}{Colors.NC}", file=sys.stderr)
        print(f"{Colors.RED}✗ Failed: {self.tests_failed}{Colors.NC}", file=sys.stderr)
        print(f"{Colors.CYAN}Total: {total}{Colors.NC}", file=sys.stderr)
        
        if self.tests_failed == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}All tests passed!{Colors.NC}", file=sys.stderr)
            return True
        else:
            print(f"{Colors.RED}{Colors.BOLD}Some tests failed!{Colors.NC}", file=sys.stderr)
            return False
    
    def api_call(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                files: Optional[Dict] = None) -> Tuple[int, Dict]:
        """Make an API call and return status code and response data"""
        url = f"{self.api_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                if files:
                    response = self.session.post(url, data=data, files=files)
                else:
                    response = self.session.post(url, json=data)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Try to parse JSON response
            try:
                response_data = response.json()
            except:
                response_data = {"raw_text": response.text}
            
            return response.status_code, response_data
            
        except Exception as e:
            self.print_error(f"API call failed: {e}")
            return 500, {"error": str(e)}
    
    def assert_status_code(self, actual: int, expected: int, description: str) -> bool:
        """Assert HTTP status code matches expected"""
        if actual == expected:
            self.print_success(f"{description}: expected {expected}, got {actual}")
            return True
        else:
            self.print_error(f"{description}: expected {expected}, got {actual}")
            return False
    
    def run_test_case(self, test_case: TestCase) -> bool:
        """Run a single test case"""
        self.print_info(f"Testing: {test_case.description}")
        
        status_code, response_data = self.api_call(
            test_case.method, 
            test_case.endpoint, 
            test_case.data
        )
        
        success = self.assert_status_code(
            status_code, 
            test_case.expected_status, 
            test_case.description
        )
        
        # Handle successful creation responses
        if success and test_case.expected_status == 201:
            resource_id = response_data.get('id')
            if resource_id:
                # Track created resources for cleanup
                if '/stations' in test_case.endpoint:
                    self.created_station_ids.append(resource_id)
                elif '/voices' in test_case.endpoint:
                    self.created_voice_ids.append(resource_id)
                elif '/stories' in test_case.endpoint:
                    self.created_story_ids.append(resource_id)
                elif '/users' in test_case.endpoint:
                    self.created_user_ids.append(resource_id)
                elif '/station-voices' in test_case.endpoint:
                    self.created_station_voice_ids.append(resource_id)
        
        # Check for validation error details on 422 responses
        if test_case.expected_status == 422 and status_code == 422:
            if any(keyword in str(response_data).lower() for keyword in 
                   ['validation', 'required', 'field', 'invalid']):
                self.print_success("Contains validation error details")
            else:
                self.print_warning("Missing detailed validation error message")
        
        return success
    
    # ============================================================================
    # STATION VALIDATION TESTS
    # ============================================================================
    
    def test_station_field_validation(self) -> bool:
        """Test station required field validation"""
        self.print_section("Station Field Validation")
        
        test_cases = [
            TestCase("empty_json", {}, 422, "Missing all required fields", "/stations"),
            TestCase("empty_name", {"name": ""}, 422, "Empty name field", "/stations"),
            TestCase("missing_max_stories", {"name": "Test"}, 422, "Missing max_stories_per_block", "/stations"),
            TestCase("missing_name", {"max_stories_per_block": 5}, 422, "Missing name field", "/stations"),
            TestCase("null_name", {"name": None, "max_stories_per_block": 5}, 422, "Null name field", "/stations"),
        ]
        
        all_passed = True
        for test_case in test_cases:
            if not self.run_test_case(test_case):
                all_passed = False
        
        return all_passed
    
    def test_station_data_type_validation(self) -> bool:
        """Test station data type validation"""
        self.print_section("Station Data Type Validation")
        
        test_cases = [
            TestCase("name_as_number", {"name": 123, "max_stories_per_block": 5}, 422, 
                    "Name should be string not number", "/stations"),
            TestCase("max_stories_as_string", {"name": "Test", "max_stories_per_block": "invalid"}, 422,
                    "Max stories should be number not string", "/stations"),
            TestCase("pause_seconds_as_string", {"name": "Test", "max_stories_per_block": 5, "pause_seconds": "invalid"}, 422,
                    "Pause seconds should be number not string", "/stations"),
            TestCase("max_stories_as_float", {"name": "Test", "max_stories_per_block": 5.5}, 422,
                    "Max stories should be integer not float", "/stations"),
            TestCase("name_as_boolean", {"name": True, "max_stories_per_block": 5}, 422,
                    "Name should be string not boolean", "/stations"),
            TestCase("name_as_array", {"name": ["array"], "max_stories_per_block": 5}, 422,
                    "Name should be string not array", "/stations"),
            TestCase("name_as_object", {"name": {"object": "test"}, "max_stories_per_block": 5}, 422,
                    "Name should be string not object", "/stations"),
        ]
        
        all_passed = True
        for test_case in test_cases:
            if not self.run_test_case(test_case):
                all_passed = False
        
        return all_passed
    
    def test_station_boundary_validation(self) -> bool:
        """Test station boundary validation"""
        self.print_section("Station Boundary Validation")
        
        # Generate long strings for testing
        long_name = 'A' * 256
        max_name = 'A' * 255
        
        test_cases = [
            TestCase("name_too_long", {"name": long_name, "max_stories_per_block": 5}, 422,
                    "Name too long (256 chars, max 255)", "/stations"),
            TestCase("name_at_max", {"name": max_name, "max_stories_per_block": 5}, 201,
                    "Name at max length (255 chars)", "/stations"),
            TestCase("max_stories_below_min", {"name": "Test", "max_stories_per_block": 0}, 422,
                    "Max stories below minimum (0, min 1)", "/stations"),
            TestCase("max_stories_at_min", {"name": "Test1", "max_stories_per_block": 1}, 201,
                    "Max stories at minimum (1)", "/stations"),
            TestCase("max_stories_at_max", {"name": "Test50", "max_stories_per_block": 50}, 201,
                    "Max stories at maximum (50)", "/stations"),
            TestCase("max_stories_above_max", {"name": "Test", "max_stories_per_block": 51}, 422,
                    "Max stories above maximum (51, max 50)", "/stations"),
            TestCase("pause_seconds_negative", {"name": "Test", "max_stories_per_block": 5, "pause_seconds": -0.1}, 422,
                    "Pause seconds negative", "/stations"),
            TestCase("pause_seconds_at_min", {"name": "Test2", "max_stories_per_block": 5, "pause_seconds": 0}, 201,
                    "Pause seconds at minimum (0)", "/stations"),
            TestCase("pause_seconds_at_max", {"name": "Test3", "max_stories_per_block": 5, "pause_seconds": 60}, 201,
                    "Pause seconds at maximum (60)", "/stations"),
            TestCase("pause_seconds_above_max", {"name": "Test", "max_stories_per_block": 5, "pause_seconds": 60.1}, 422,
                    "Pause seconds above maximum (60.1, max 60)", "/stations"),
        ]
        
        all_passed = True
        for test_case in test_cases:
            if not self.run_test_case(test_case):
                all_passed = False
        
        return all_passed
    
    def test_station_unique_constraint(self) -> bool:
        """Test station unique name constraint"""
        self.print_section("Station Unique Name Constraint")
        
        unique_name = f"UniqueConstraintTest_{int(time.time())}"
        
        # Create first station
        self.print_info(f"Creating station with name: {unique_name}")
        status_code, response_data = self.api_call(
            "POST", "/stations", 
            {"name": unique_name, "max_stories_per_block": 5}
        )
        
        if self.assert_status_code(status_code, 201, "Create first station"):
            station_id = response_data.get('id')
            if station_id:
                self.created_station_ids.append(station_id)
            
            # Try to create duplicate
            self.print_info("Attempting to create duplicate station name")
            dup_status, _ = self.api_call(
                "POST", "/stations",
                {"name": unique_name, "max_stories_per_block": 3}
            )
            
            return self.assert_status_code(dup_status, 409, "Duplicate station name should return 409 Conflict")
        
        return False
    
    # ============================================================================
    # VOICE VALIDATION TESTS
    # ============================================================================
    
    def test_voice_validation(self) -> bool:
        """Test voice validation"""
        self.print_section("Voice Validation")
        
        long_name = 'V' * 256
        max_name = 'V' * 255
        
        test_cases = [
            TestCase("missing_name", {}, 422, "Missing name field", "/voices"),
            TestCase("empty_name", {"name": ""}, 422, "Empty name field", "/voices"),
            TestCase("null_name", {"name": None}, 422, "Null name field", "/voices"),
            TestCase("name_as_number", {"name": 123}, 422, "Name should be string not number", "/voices"),
            TestCase("valid_voice", {"name": "Valid Voice"}, 201, "Valid voice creation", "/voices"),
            TestCase("name_too_long", {"name": long_name}, 422, "Name too long (256 chars)", "/voices"),
            TestCase("name_at_max", {"name": max_name}, 201, "Name at max length (255 chars)", "/voices"),
        ]
        
        all_passed = True
        for test_case in test_cases:
            if not self.run_test_case(test_case):
                all_passed = False
        
        return all_passed
    
    # ============================================================================
    # USER VALIDATION TESTS
    # ============================================================================
    
    def test_user_validation(self) -> bool:
        """Test user validation"""
        self.print_section("User Validation")
        
        # Generate test strings
        long_username = 'u' * 101
        max_username = 'u' * 100
        long_fullname = 'F' * 256
        max_fullname = 'F' * 255
        long_email = 'e' * 246 + '@test.com'  # 256+ chars total
        max_email = 'e' * 245 + '@test.com'   # 255 chars total
        
        test_cases = [
            # Basic field validation
            TestCase("missing_fields", {}, 422, "Missing all required fields", "/users"),
            TestCase("empty_username", {"username": ""}, 422, "Empty username", "/users"),
            TestCase("missing_full_name", {"username": "test"}, 422, "Missing full_name", "/users"),
            TestCase("empty_full_name", {"username": "test", "full_name": ""}, 422, "Empty full_name", "/users"),
            TestCase("username_too_short", {"username": "ab"}, 422, "Username too short (min 3 chars)", "/users"),
            TestCase("missing_password", {"username": "valid_user", "full_name": "Test User"}, 422, "Missing password for new user", "/users"),
            TestCase("password_too_short", {"username": "valid_user", "full_name": "Test User", "password": "short"}, 422, "Password too short (min 8 chars)", "/users"),
            TestCase("valid_user", {"username": "valid_user", "full_name": "Test User", "password": "validpassword"}, 201, "Valid user creation", "/users"),
            
            # Username pattern validation
            TestCase("username_with_at", {"username": "test@user", "full_name": "Test", "password": "password123"}, 422, "Username with @ symbol", "/users"),
            TestCase("username_with_space", {"username": "test user", "full_name": "Test", "password": "password123"}, 422, "Username with space", "/users"),
            TestCase("username_with_dot", {"username": "test.user", "full_name": "Test", "password": "password123"}, 422, "Username with dot", "/users"),
            TestCase("username_with_underscore", {"username": "test_user", "full_name": "Test", "password": "password123"}, 201, "Username with underscore (valid)", "/users"),
            TestCase("username_with_hyphen", {"username": "test-user", "full_name": "Test", "password": "password123"}, 201, "Username with hyphen (valid)", "/users"),
            TestCase("username_alphanumeric", {"username": "testuser123", "full_name": "Test", "password": "password123"}, 201, "Username alphanumeric (valid)", "/users"),
            
            # Length boundaries
            TestCase("username_too_long", {"username": long_username, "full_name": "Test", "password": "password123"}, 422, "Username too long (101 chars)", "/users"),
            TestCase("username_at_max", {"username": max_username, "full_name": "Test", "password": "password123"}, 201, "Username at max length (100 chars)", "/users"),
            TestCase("fullname_too_long", {"username": "testuser", "full_name": long_fullname, "password": "password123"}, 422, "Full name too long (256 chars)", "/users"),
            TestCase("fullname_at_max", {"username": "testuser2", "full_name": max_fullname, "password": "password123"}, 201, "Full name at max length (255 chars)", "/users"),
            TestCase("email_too_long", {"username": "testuser3", "full_name": "Test", "email": long_email, "password": "password123"}, 422, "Email too long (256+ chars)", "/users"),
            TestCase("email_at_max", {"username": "testuser4", "full_name": "Test", "email": max_email, "password": "password123"}, 201, "Email at max length (255 chars)", "/users"),
            
            # Email format validation
            TestCase("invalid_email", {"username": "testuser5", "full_name": "Test", "email": "invalid-email", "password": "password123"}, 422, "Invalid email format", "/users"),
            TestCase("valid_email", {"username": "testuser6", "full_name": "Test", "email": "valid@example.com", "password": "password123"}, 201, "Valid email format", "/users"),
            TestCase("empty_email", {"username": "testuser7", "full_name": "Test", "email": "", "password": "password123"}, 422, "Empty email (should be null or valid)", "/users"),
            TestCase("no_email", {"username": "testuser8", "full_name": "Test", "password": "password123"}, 201, "No email field (valid)", "/users"),
            
            # Role validation
            TestCase("invalid_role", {"username": "testuser9", "full_name": "Test", "password": "password123", "role": "invalid"}, 422, "Invalid role", "/users"),
            TestCase("admin_role", {"username": "testuser10", "full_name": "Test", "password": "password123", "role": "admin"}, 201, "Valid admin role", "/users"),
            TestCase("editor_role", {"username": "testuser11", "full_name": "Test", "password": "password123", "role": "editor"}, 201, "Valid editor role", "/users"),
            TestCase("viewer_role", {"username": "testuser12", "full_name": "Test", "password": "password123", "role": "viewer"}, 201, "Valid viewer role", "/users"),
        ]
        
        all_passed = True
        for test_case in test_cases:
            if not self.run_test_case(test_case):
                all_passed = False
        
        return all_passed
    
    def test_user_unique_constraints(self) -> bool:
        """Test user unique constraints"""
        self.print_section("User Unique Constraints")
        
        timestamp = int(time.time())
        username = f"uniquetest{timestamp}"
        email = f"uniquetest{timestamp}@example.com"
        
        # Create first user
        self.print_info(f"Creating user with username: {username} and email: {email}")
        status_code, response_data = self.api_call(
            "POST", "/users",
            {
                "username": username,
                "full_name": "Test User",
                "email": email,
                "password": "password123"
            }
        )
        
        if self.assert_status_code(status_code, 201, "Create first user"):
            user_id = response_data.get('id')
            if user_id:
                self.created_user_ids.append(user_id)
            
            # Test duplicate username
            self.print_info("Testing duplicate username")
            dup_status, _ = self.api_call(
                "POST", "/users",
                {
                    "username": username,
                    "full_name": "Another User",
                    "email": f"different{timestamp}@example.com",
                    "password": "password123"
                }
            )
            
            username_test = self.assert_status_code(dup_status, 409, "Duplicate username should return 409 Conflict")
            
            # Test duplicate email
            self.print_info("Testing duplicate email")
            dup_email_status, _ = self.api_call(
                "POST", "/users",
                {
                    "username": f"different{timestamp}",
                    "full_name": "Another User",
                    "email": email,
                    "password": "password123"
                }
            )
            
            email_test = self.assert_status_code(dup_email_status, 409, "Duplicate email should return 409 Conflict")
            
            return username_test and email_test
        
        return False
    
    # ============================================================================
    # STORY VALIDATION TESTS
    # ============================================================================
    
    def setup_story_test_data(self):
        """Create test data needed for story validation"""
        if not self.created_voice_ids:
            self.print_info("Creating test voice for story validation")
            status_code, response_data = self.api_call(
                "POST", "/voices", {"name": "Story Test Voice"}
            )
            if status_code == 201:
                voice_id = response_data.get('id')
                if voice_id:
                    self.created_voice_ids.append(voice_id)
    
    def test_story_validation(self) -> bool:
        """Test story validation with multipart form data"""
        self.print_section("Story Validation")
        
        # Setup test data
        self.setup_story_test_data()
        
        # Test required fields using requests with multipart data
        test_cases = [
            {"data": {"title": "", "text": "Test text", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Empty title"},
            {"data": {"text": "", "title": "Test Title", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Empty text"},
            {"data": {"title": "Test Title", "text": "Test text", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Missing start_date"},
            {"data": {"title": "Test Title", "text": "Test text", "start_date": "2024-12-01"}, 
             "expected": 422, "description": "Missing end_date"},
            {"data": {"title": "Test Title", "text": "Test text", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 201, "description": "Valid minimal story"},
        ]
        
        all_passed = True
        for test_case in test_cases:
            self.print_info(f"Testing: {test_case['description']}")
            
            # Use requests directly for multipart form data
            try:
                response = self.session.post(f"{self.api_url}/stories", data=test_case['data'])
                
                success = self.assert_status_code(
                    response.status_code, 
                    test_case['expected'], 
                    test_case['description']
                )
                
                if not success:
                    all_passed = False
                
                # Handle successful creation
                if success and test_case['expected'] == 201:
                    try:
                        response_data = response.json()
                        story_id = response_data.get('id')
                        if story_id:
                            self.created_story_ids.append(story_id)
                    except:
                        pass
            
            except Exception as e:
                self.print_error(f"Story validation test failed: {e}")
                all_passed = False
        
        return all_passed
    
    def test_story_boundary_validation(self) -> bool:
        """Test story boundary validation"""
        self.print_section("Story Boundary Validation")
        
        # Generate test strings
        long_title = 'T' * 501
        max_title = 'T' * 500
        long_text = 'X' * 10000
        
        test_cases = [
            {"data": {"title": long_title, "text": "Test text", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Title too long (501 chars, max 500)"},
            {"data": {"title": max_title, "text": "Test text", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 201, "description": "Title at max length (500 chars)"},
            {"data": {"title": "Long Text Test", "text": long_text, "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 201, "description": "Very long text content should be accepted"},
        ]
        
        all_passed = True
        for test_case in test_cases:
            self.print_info(f"Testing: {test_case['description']}")
            
            try:
                response = self.session.post(f"{self.api_url}/stories", data=test_case['data'])
                
                success = self.assert_status_code(
                    response.status_code, 
                    test_case['expected'], 
                    test_case['description']
                )
                
                if not success:
                    all_passed = False
                
                # Handle successful creation
                if success and test_case['expected'] == 201:
                    try:
                        response_data = response.json()
                        story_id = response_data.get('id')
                        if story_id:
                            self.created_story_ids.append(story_id)
                    except:
                        pass
            
            except Exception as e:
                self.print_error(f"Story boundary test failed: {e}")
                all_passed = False
        
        return all_passed
    
    def test_story_date_validation(self) -> bool:
        """Test story date validation"""
        self.print_section("Story Date Validation")
        
        test_cases = [
            {"data": {"title": "Date Test 1", "text": "Test", "start_date": "invalid-date", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Invalid start_date format"},
            {"data": {"title": "Date Test 2", "text": "Test", "start_date": "2024-12-01", "end_date": "invalid-date"}, 
             "expected": 422, "description": "Invalid end_date format"},
            {"data": {"title": "Date Test 3", "text": "Test", "start_date": "2024/12/01", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Wrong date format (slashes)"},
            {"data": {"title": "Date Test 4", "text": "Test", "start_date": "01-12-2024", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Wrong date format (DD-MM-YYYY)"},
            {"data": {"title": "Date Test 5", "text": "Test", "start_date": "2024-13-01", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Invalid month (13)"},
            {"data": {"title": "Date Test 6", "text": "Test", "start_date": "2024-12-32", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Invalid day (32)"},
            {"data": {"title": "Date Test 7", "text": "Test", "start_date": "2024-02-30", "end_date": "2024-12-31"}, 
             "expected": 422, "description": "Invalid date (Feb 30)"},
            {"data": {"title": "Date Test 8", "text": "Test", "start_date": "2024-12-01", "end_date": "2024-12-31"}, 
             "expected": 201, "description": "Valid date range"},
            {"data": {"title": "Date Test 9", "text": "Test", "start_date": "2024-12-31", "end_date": "2024-12-01"}, 
             "expected": 422, "description": "End date before start date"},
        ]
        
        all_passed = True
        for test_case in test_cases:
            self.print_info(f"Testing: {test_case['description']}")
            
            try:
                response = self.session.post(f"{self.api_url}/stories", data=test_case['data'])
                
                success = self.assert_status_code(
                    response.status_code, 
                    test_case['expected'], 
                    test_case['description']
                )
                
                if not success:
                    all_passed = False
                
                # Handle successful creation
                if success and test_case['expected'] == 201:
                    try:
                        response_data = response.json()
                        story_id = response_data.get('id')
                        if story_id:
                            self.created_story_ids.append(story_id)
                    except:
                        pass
            
            except Exception as e:
                self.print_error(f"Story date test failed: {e}")
                all_passed = False
        
        return all_passed
    
    # ============================================================================
    # INPUT SANITIZATION TESTS
    # ============================================================================
    
    def test_sql_injection_attempts(self) -> bool:
        """Test SQL injection sanitization"""
        self.print_section("SQL Injection Sanitization Tests")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1 --",
            '" OR "1"="1',
            "'; INSERT INTO users (username) VALUES ('hacker'); --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
        ]
        
        all_passed = True
        
        # Test SQL injection in station names
        self.print_info("Testing SQL injection in station names")
        for payload in sql_payloads:
            status_code, response_data = self.api_call(
                "POST", "/stations", 
                {"name": payload, "max_stories_per_block": 5}
            )
            
            # Should either reject malicious input (422) or safely store it (201)
            if status_code == 201:
                self.print_success("SQL injection payload safely stored as literal string")
                station_id = response_data.get('id')
                if station_id:
                    self.created_station_ids.append(station_id)
            elif status_code == 422:
                self.print_success("SQL injection payload correctly rejected")
            else:
                self.print_error(f"Unexpected response to SQL injection attempt: HTTP {status_code}")
                all_passed = False
        
        # Test SQL injection in user data
        self.print_info("Testing SQL injection in user creation")
        user_payload = "admin'; DROP TABLE stories; --"
        status_code, response_data = self.api_call(
            "POST", "/users",
            {
                "username": user_payload,
                "full_name": "Test",
                "password": "password123"
            }
        )
        
        if status_code == 201:
            self.print_success("SQL injection in username safely stored")
            user_id = response_data.get('id')
            if user_id:
                self.created_user_ids.append(user_id)
        elif status_code in [422, 400]:
            self.print_success("SQL injection in username correctly rejected")
        else:
            self.print_error(f"Unexpected response to SQL injection in username: HTTP {status_code}")
            all_passed = False
        
        return all_passed
    
    def test_xss_attempts(self) -> bool:
        """Test XSS sanitization"""
        self.print_section("XSS Sanitization Tests")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "'><script>alert('XSS')</script>",
            '"><script>alert(\'XSS\')</script>',
            "<script src=//evil.com/xss.js></script>",
        ]
        
        all_passed = True
        
        # Test XSS in story content
        self.print_info("Testing XSS in story titles and text")
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    f"{self.api_url}/stories", 
                    data={
                        "title": payload,
                        "text": "Test text with XSS in title",
                        "start_date": "2024-12-01",
                        "end_date": "2024-12-31"
                    }
                )
                
                if response.status_code == 201:
                    self.print_success("XSS payload in title safely stored")
                    try:
                        response_data = response.json()
                        story_id = response_data.get('id')
                        if story_id:
                            self.created_story_ids.append(story_id)
                            
                            # Verify the data was stored but not executed
                            verify_status, verify_data = self.api_call("GET", f"/stories/{story_id}")
                            if verify_status == 200:
                                stored_title = verify_data.get('title', '')
                                if payload in stored_title:
                                    self.print_success("XSS payload stored as literal text (not executed)")
                                else:
                                    self.print_info("XSS payload may have been sanitized during storage")
                    except:
                        pass
                elif response.status_code in [422, 400]:
                    self.print_success("XSS payload correctly rejected")
                else:
                    self.print_error(f"Unexpected response to XSS attempt: HTTP {response.status_code}")
                    all_passed = False
            
            except Exception as e:
                self.print_error(f"XSS test failed: {e}")
                all_passed = False
        
        return all_passed
    
    def test_path_traversal_attempts(self) -> bool:
        """Test path traversal sanitization"""
        self.print_section("Path Traversal Sanitization Tests")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../../../../../../../../etc/passwd",
        ]
        
        all_passed = True
        
        # Test path traversal in names
        self.print_info("Testing path traversal attempts in names")
        for payload in traversal_payloads:
            status_code, response_data = self.api_call(
                "POST", "/stations", 
                {"name": payload, "max_stories_per_block": 5}
            )
            
            if status_code == 201:
                self.print_success("Path traversal payload safely stored as literal string")
                station_id = response_data.get('id')
                if station_id:
                    self.created_station_ids.append(station_id)
            elif status_code in [422, 400]:
                self.print_success("Path traversal payload correctly rejected")
            else:
                self.print_error(f"Unexpected response to path traversal: HTTP {status_code}")
                all_passed = False
        
        return all_passed
    
    # ============================================================================
    # FILE UPLOAD VALIDATION TESTS
    # ============================================================================
    
    def test_audio_file_upload_validation(self) -> bool:
        """Test audio file upload validation"""
        self.print_section("Audio File Upload Validation")
        
        # Create temporary test files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create a minimal valid WAV file
            valid_wav = temp_path / "valid.wav"
            with open(valid_wav, 'wb') as f:
                # Minimal WAV header
                f.write(b'\x52\x49\x46\x46\x24\x08\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x02\x00\x22\x56\x00\x00\x88\x58\x01\x00\x04\x00\x10\x00\x64\x61\x74\x61\x00\x08\x00\x00')
            
            # Create invalid files
            text_file = temp_path / "text_file.wav"
            with open(text_file, 'w') as f:
                f.write("Not an audio file")
            
            xml_file = temp_path / "xml_file.wav"
            with open(xml_file, 'w') as f:
                f.write("<?xml version='1.0'?><test>xml</test>")
            
            all_passed = True
            
            # Test story audio upload validation
            if self.created_voice_ids:
                voice_id = self.created_voice_ids[0]
                
                # Test valid audio file
                self.print_info("Testing valid audio file upload")
                try:
                    with open(valid_wav, 'rb') as f:
                        response = self.session.post(
                            f"{self.api_url}/stories",
                            data={
                                "title": "Audio Test Valid",
                                "text": "Test with valid audio",
                                "start_date": "2024-12-01",
                                "end_date": "2024-12-31",
                                "voice_id": voice_id
                            },
                            files={"audio": f}
                        )
                    
                    if self.assert_status_code(response.status_code, 201, "Valid audio file upload"):
                        try:
                            response_data = response.json()
                            story_id = response_data.get('id')
                            if story_id:
                                self.created_story_ids.append(story_id)
                        except:
                            pass
                    else:
                        all_passed = False
                
                except Exception as e:
                    self.print_error(f"Valid audio test failed: {e}")
                    all_passed = False
                
                # Test invalid audio file
                self.print_info("Testing invalid audio file upload")
                try:
                    with open(text_file, 'rb') as f:
                        response = self.session.post(
                            f"{self.api_url}/stories",
                            data={
                                "title": "Audio Test Invalid",
                                "text": "Test with invalid audio",
                                "start_date": "2024-12-01",
                                "end_date": "2024-12-31",
                                "voice_id": voice_id
                            },
                            files={"audio": f}
                        )
                    
                    # Should either accept it (backend validates later) or reject it
                    if response.status_code in [422, 400]:
                        self.print_success("Invalid audio file correctly rejected")
                    elif response.status_code == 201:
                        self.print_warning("Invalid audio file accepted (may be validated later)")
                        try:
                            response_data = response.json()
                            story_id = response_data.get('id')
                            if story_id:
                                self.created_story_ids.append(story_id)
                        except:
                            pass
                    else:
                        self.print_error(f"Unexpected response to invalid audio file: HTTP {response.status_code}")
                        all_passed = False
                
                except Exception as e:
                    self.print_error(f"Invalid audio test failed: {e}")
                    all_passed = False
            
            return all_passed
    
    # ============================================================================
    # STATION-VOICE VALIDATION TESTS
    # ============================================================================
    
    def setup_station_voice_test_data(self):
        """Setup test data for station-voice validation"""
        # Create station if needed
        if not self.created_station_ids:
            self.print_info("Creating test station for station-voice validation")
            status_code, response_data = self.api_call(
                "POST", "/stations", 
                {"name": "StationVoice Test Station", "max_stories_per_block": 5}
            )
            if status_code == 201:
                station_id = response_data.get('id')
                if station_id:
                    self.created_station_ids.append(station_id)
        
        # Create voice if needed
        if not self.created_voice_ids:
            self.print_info("Creating test voice for station-voice validation")
            status_code, response_data = self.api_call(
                "POST", "/voices", {"name": "StationVoice Test Voice"}
            )
            if status_code == 201:
                voice_id = response_data.get('id')
                if voice_id:
                    self.created_voice_ids.append(voice_id)
    
    def test_station_voice_validation(self) -> bool:
        """Test station-voice validation"""
        self.print_section("Station-Voice Validation")
        
        # Setup test data
        self.setup_station_voice_test_data()
        
        if not self.created_station_ids or not self.created_voice_ids:
            self.print_error("Need station and voice for station-voice tests")
            return False
        
        station_id = self.created_station_ids[0]
        voice_id = self.created_voice_ids[0]
        
        # Test validation using multipart form data
        test_cases = [
            {"data": {"voice_id": voice_id}, "expected": 422, "description": "Missing station_id"},
            {"data": {"station_id": station_id}, "expected": 422, "description": "Missing voice_id"},
            {"data": {"station_id": 99999, "voice_id": voice_id}, "expected": 422, "description": "Invalid station_id"},
            {"data": {"station_id": station_id, "voice_id": 99999}, "expected": 422, "description": "Invalid voice_id"},
            {"data": {"station_id": station_id, "voice_id": voice_id}, "expected": 201, "description": "Valid station-voice relationship"},
            {"data": {"station_id": station_id, "voice_id": voice_id, "mix_point": -1}, "expected": 422, "description": "Negative mix_point"},
            {"data": {"station_id": station_id, "voice_id": voice_id, "mix_point": 301}, "expected": 422, "description": "Mix_point above maximum (300)"},
            {"data": {"station_id": station_id, "voice_id": voice_id, "mix_point": 0}, "expected": 201, "description": "Mix_point at minimum (0)"},
            {"data": {"station_id": station_id, "voice_id": voice_id, "mix_point": 300}, "expected": 201, "description": "Mix_point at maximum (300)"},
        ]
        
        all_passed = True
        for test_case in test_cases:
            self.print_info(f"Testing: {test_case['description']}")
            
            try:
                response = self.session.post(f"{self.api_url}/station-voices", data=test_case['data'])
                
                success = self.assert_status_code(
                    response.status_code, 
                    test_case['expected'], 
                    test_case['description']
                )
                
                if not success:
                    all_passed = False
                
                # Handle successful creation
                if success and test_case['expected'] == 201:
                    try:
                        response_data = response.json()
                        sv_id = response_data.get('id')
                        if sv_id:
                            self.created_station_voice_ids.append(sv_id)
                    except:
                        pass
            
            except Exception as e:
                self.print_error(f"Station-voice test failed: {e}")
                all_passed = False
        
        return all_passed
    
    # ============================================================================
    # BUSINESS RULE VALIDATION TESTS
    # ============================================================================
    
    def test_business_rule_validation(self) -> bool:
        """Test business rule validation"""
        self.print_section("Business Rule Validation")
        
        all_passed = True
        
        # Test story date logic
        self.print_info("Testing story date business rules")
        
        # Test end date before start date
        try:
            response = self.session.post(
                f"{self.api_url}/stories",
                data={
                    "title": "Date Logic Test",
                    "text": "End date before start date",
                    "start_date": "2024-12-31",
                    "end_date": "2024-12-01"
                }
            )
            
            if not self.assert_status_code(response.status_code, 422, "End date before start date should be rejected"):
                all_passed = False
        
        except Exception as e:
            self.print_error(f"Date logic test failed: {e}")
            all_passed = False
        
        # Test very old dates
        try:
            response = self.session.post(
                f"{self.api_url}/stories",
                data={
                    "title": "Old Date Test",
                    "text": "Very old date",
                    "start_date": "1990-01-01",
                    "end_date": "1990-01-02"
                }
            )
            
            if response.status_code == 201:
                self.print_success("Old dates accepted (no business rule restriction)")
                try:
                    response_data = response.json()
                    story_id = response_data.get('id')
                    if story_id:
                        self.created_story_ids.append(story_id)
                except:
                    pass
            elif response.status_code == 422:
                self.print_success("Old dates rejected by business rules")
            else:
                self.print_warning(f"Unexpected response for old dates: HTTP {response.status_code}")
        
        except Exception as e:
            self.print_error(f"Old date test failed: {e}")
            all_passed = False
        
        # Test future dates
        try:
            response = self.session.post(
                f"{self.api_url}/stories",
                data={
                    "title": "Future Date Test",
                    "text": "Far future date",
                    "start_date": "2099-01-01",
                    "end_date": "2099-01-02"
                }
            )
            
            if response.status_code == 201:
                self.print_success("Future dates accepted")
                try:
                    response_data = response.json()
                    story_id = response_data.get('id')
                    if story_id:
                        self.created_story_ids.append(story_id)
                except:
                    pass
            elif response.status_code == 422:
                self.print_success("Far future dates rejected by business rules")
            else:
                self.print_warning(f"Unexpected response for future dates: HTTP {response.status_code}")
        
        except Exception as e:
            self.print_error(f"Future date test failed: {e}")
            all_passed = False
        
        return all_passed
    
    # ============================================================================
    # CLEANUP AND MAIN EXECUTION
    # ============================================================================
    
    def cleanup(self):
        """Clean up all created resources"""
        self.print_info("Cleaning up validation tests...")
        
        # Delete all created resources
        for story_id in self.created_story_ids:
            try:
                self.api_call("DELETE", f"/stories/{story_id}")
            except:
                pass
        
        for sv_id in self.created_station_voice_ids:
            try:
                self.api_call("DELETE", f"/station-voices/{sv_id}")
            except:
                pass
        
        for user_id in self.created_user_ids:
            try:
                self.api_call("DELETE", f"/users/{user_id}")
            except:
                pass
        
        for voice_id in self.created_voice_ids:
            try:
                self.api_call("DELETE", f"/voices/{voice_id}")
            except:
                pass
        
        for station_id in self.created_station_ids:
            try:
                self.api_call("DELETE", f"/stations/{station_id}")
            except:
                pass
        
        # Reset arrays
        self.created_station_ids = []
        self.created_voice_ids = []
        self.created_story_ids = []
        self.created_user_ids = []
        self.created_station_voice_ids = []
    
    def run_all_tests(self) -> bool:
        """Run all validation tests"""
        self.print_header("Comprehensive Validation Tests")
        
        test_functions = [
            self.test_station_field_validation,
            self.test_station_data_type_validation,
            self.test_station_boundary_validation,
            self.test_station_unique_constraint,
            self.test_voice_validation,
            self.test_user_validation,
            self.test_user_unique_constraints,
            self.test_story_validation,
            self.test_story_boundary_validation,
            self.test_story_date_validation,
            self.test_station_voice_validation,
            self.test_sql_injection_attempts,
            self.test_xss_attempts,
            self.test_path_traversal_attempts,
            self.test_audio_file_upload_validation,
            self.test_business_rule_validation,
        ]
        
        failed = 0
        
        for test_func in test_functions:
            try:
                if test_func():
                    self.print_success(f"✓ {test_func.__name__} passed")
                else:
                    self.print_error(f"✗ {test_func.__name__} failed")
                    failed += 1
            except Exception as e:
                self.print_error(f"✗ {test_func.__name__} failed with exception: {e}")
                failed += 1
            
            print()  # Add spacing between tests
        
        self.cleanup()
        
        success = self.print_summary()
        
        return success


def main():
    """Main entry point"""
    tester = ValidationTester()
    
    try:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Tests interrupted by user{Colors.NC}", file=sys.stderr)
        tester.cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {e}{Colors.NC}", file=sys.stderr)
        tester.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()