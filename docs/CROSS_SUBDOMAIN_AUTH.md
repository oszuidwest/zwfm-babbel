# Cross-Subdomain Authentication Setup

This document explains how to configure Babbel for cross-subdomain authentication, allowing a frontend on one subdomain to authenticate with an API on another subdomain.

## Problem

When your frontend and backend API are on different subdomains:
- Frontend: `https://babbel.zuidwest.cloud`
- Backend API: `https://babbel-api.zuidwest.cloud`

By default, cookies set by the API are not accessible to the frontend because they're scoped to the API subdomain only.

## Solution

Configure cookies to be shared across all subdomains using the following environment variables:

### Required Environment Variables

```bash
# Share cookies across all *.zuidwest.cloud subdomains
BABBEL_COOKIE_DOMAIN=.zuidwest.cloud

# Required for cross-origin requests between subdomains
BABBEL_COOKIE_SAMESITE=none

# Ensure HTTPS is used (required when SameSite=none)
BABBEL_ENV=production

# Allow frontend origin for CORS
BABBEL_ALLOWED_ORIGINS=https://babbel.zuidwest.cloud
```

### Important Notes

1. **Leading Dot**: The `.` before the domain (`.zuidwest.cloud`) is essential - it tells browsers to share the cookie with all subdomains.

2. **SameSite=None**: Required for cookies to be sent in cross-site requests (different subdomains are considered cross-site).

3. **Secure Flag**: Automatically set when `BABBEL_ENV=production`. Required when using `SameSite=None`.

4. **CORS Origins**: Must include your frontend URL to allow browser-based requests.

## Configuration Examples

### Production Setup (zuidwest.cloud)

Use the provided `.env.zuidwest.example` as a template:

```bash
cp .env.zuidwest.example .env
# Edit .env with your actual values
docker-compose -f docker-compose.prod.yml up -d
```

### Local Development (Same Domain)

For local development where frontend and backend are on the same domain:

```bash
# No cookie domain needed for localhost
BABBEL_COOKIE_DOMAIN=

# Can use lax for same-site
BABBEL_COOKIE_SAMESITE=lax

# Development mode (cookies not marked as Secure)
BABBEL_ENV=development

# Allow localhost origins
BABBEL_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Multiple Environments

For staging/production with different domains:

```bash
# Production
BABBEL_COOKIE_DOMAIN=.production.com
BABBEL_ALLOWED_ORIGINS=https://app.production.com

# Staging
BABBEL_COOKIE_DOMAIN=.staging.com
BABBEL_ALLOWED_ORIGINS=https://app.staging.com
```

## Testing

After configuration, verify that:

1. **Login works**: Users can log in from the frontend
2. **Sessions persist**: Refresh the page and remain logged in
3. **Cookie is set correctly**: In browser DevTools, check that the cookie has:
   - Domain: `.zuidwest.cloud`
   - SameSite: `None`
   - Secure: ✓
   - HttpOnly: ✓

## Troubleshooting

### Cookie not being set
- Ensure HTTPS is used (required for `SameSite=None`)
- Check browser console for CORS errors
- Verify `BABBEL_ALLOWED_ORIGINS` includes your frontend URL

### Session not persisting
- Verify cookie domain starts with `.` for cross-subdomain
- Check that `SameSite` is set to `none`
- Ensure frontend includes credentials in API requests

### CORS errors
- Add frontend URL to `BABBEL_ALLOWED_ORIGINS`
- Ensure the URL matches exactly (including protocol and port)

## Security Considerations

- **HttpOnly**: Always enabled to prevent XSS attacks
- **Secure**: Automatically enabled in production to ensure HTTPS-only transmission
- **SameSite**: Use `strict` or `lax` when possible for better CSRF protection
- **Domain Scope**: Be specific with cookie domain to limit exposure