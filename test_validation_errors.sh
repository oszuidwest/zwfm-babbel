#!/bin/bash

# Simple test to verify that validation errors return 422 instead of 400
# This tests the key changes we made

echo "Testing validation error responses..."

# Start the server if needed (optional - assumes it's running)
API_BASE="${API_BASE:-http://localhost:8080}"

echo "Testing user update with no fields (should return 422)..."
curl -s -X PUT "$API_BASE/api/v1/users/1" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "HTTP Status: %{http_code}\n" \
  -o /tmp/response.json

echo "Response body:"
cat /tmp/response.json | jq '.' 2>/dev/null || cat /tmp/response.json
echo

echo "Testing station-voice update with invalid mix_point (should return 422)..."
curl -s -X POST "$API_BASE/api/v1/station-voices" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "station_id=1&voice_id=1&mix_point=500" \
  -w "HTTP Status: %{http_code}\n" \
  -o /tmp/response2.json

echo "Response body:"
cat /tmp/response2.json | jq '.' 2>/dev/null || cat /tmp/response2.json
echo

echo "Testing story update with invalid status (should return 422)..."
curl -s -X PUT "$API_BASE/api/v1/stories/1" \
  -H "Content-Type: application/json" \
  -d '{"status": "invalid_status"}' \
  -w "HTTP Status: %{http_code}\n" \
  -o /tmp/response3.json

echo "Response body:"
cat /tmp/response3.json | jq '.' 2>/dev/null || cat /tmp/response3.json
echo

echo "Testing bulletin generation with invalid date (should return 422)..."
curl -s -X POST "$API_BASE/api/v1/stations/1/bulletins" \
  -H "Content-Type: application/json" \
  -d '{"date": "invalid-date-format"}' \
  -w "HTTP Status: %{http_code}\n" \
  -o /tmp/response4.json

echo "Response body:"
cat /tmp/response4.json | jq '.' 2>/dev/null || cat /tmp/response4.json
echo

# Clean up
rm -f /tmp/response*.json

echo "Validation error tests completed!"