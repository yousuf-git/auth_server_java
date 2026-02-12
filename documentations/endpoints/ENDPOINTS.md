# Spring Security JWT - API Endpoints Reference

> Auto-generated endpoint documentation for coding agent context.
> Base URL: `http://localhost:8080`

---

## Table of Contents

- [Global Information](#global-information)
- [Auth Endpoints (Public)](#auth-endpoints-public)
- [User Endpoints (Authenticated)](#user-endpoints-authenticated)
- [Admin Endpoints (ROLE_ADMIN)](#admin-endpoints-role_admin)
- [Manager Endpoints (ROLE_PLANT_MANAGER or ROLE_ADMIN)](#manager-endpoints-role_plant_manager-or-role_admin)
- [OAuth2 Endpoints](#oauth2-endpoints)
- [Test Endpoints](#test-endpoints)
- [Other Endpoints](#other-endpoints)

---

## Global Information

### Authentication Mechanism

| Property | Value |
|---|---|
| Access Token Type | JWT Bearer token |
| Access Token Header | `Authorization: Bearer <token>` |
| Refresh Token Storage | HttpOnly secure cookie named `refreshToken` |
| Access Token Default Expiry | 5 minutes (configurable) |
| Refresh Token Default Expiry | 7 days (configurable) |
| Token Rotation | Refresh tokens are rotated on each use; old token is revoked |
| Token Theft Detection | If a revoked refresh token is reused, the entire token family is revoked |

### Roles

| Role | Description |
|---|---|
| `ROLE_CUSTOMER` | Default role assigned to new users |
| `ROLE_PLANT_MANAGER` | Manager role with elevated access |
| `ROLE_ADMIN` | Administrator with full access to all endpoints |

### Auth Providers

| Provider | Status |
|---|---|
| `LOCAL` | Email/password authentication (active) |
| `GOOGLE` | Google OAuth2 (active) |
| `GITHUB` | GitHub OAuth2 (infrastructure ready) |
| `FACEBOOK` | Facebook OAuth2 (infrastructure ready) |

### Error Response Formats

| Scenario | Status Code | Response Body |
|---|---|---|
| Validation errors | 400 | `{ "field1": "error message", "field2": "error message" }` |
| Business errors | 400 / 401 / 403 / 404 | `{ "message": "Error description" }` |
| Rate limiting | 429 | `{ "message": "Too many requests. Please try again later." }` + `Retry-After` header |
| Server errors | 500 | `{ "message": "An unexpected error occurred" }` |

### Rate Limiting

| Endpoint | Limit | Retry-After |
|---|---|---|
| `POST /auth/signin` | 10 requests/minute per IP | 60 seconds |
| `POST /auth/signup` | 10 requests/minute per IP | 60 seconds |
| `POST /auth/refresh` | 20 requests/minute per IP | 60 seconds |

### Security Headers

All responses include:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## Auth Endpoints (Public)

**Base path:** `/auth`
**Authentication:** None required

---

### 1. POST /auth/signup

Register a new user account.

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `email` | string | `@Email` | Yes | Valid email address |
| `password` | string | `@Size(min=6, max=30)` | Yes | User password |
| `role` | string | — | No | One of: `customer`, `admin`, `manager`, `plant_manager`, `ROLE_CUSTOMER`, `ROLE_ADMIN`, `ROLE_PLANT_MANAGER`. Defaults to `ROLE_CUSTOMER` |

**Response 201 (Created):** AuthResponse

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "userId": 1,
  "email": "user@example.com",
  "role": "ROLE_CUSTOMER",
  "expiresIn": 300000
}
```

Also sets `refreshToken` as an HttpOnly cookie.

**Response 400 (Bad Request):**

```json
{ "message": "Email already exists !" }
```

Or validation errors:

```json
{ "email": "must be a valid email", "password": "size must be between 6 and 30" }
```

**curl Example:**

```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "newuser@example.com",
    "password": "secret123",
    "role": "customer"
  }'
```

---

### 2. POST /auth/signin

Authenticate with email and password.

**Request Body:**

| Field | Type | Validation | Required |
|---|---|---|---|
| `email` | string | `@Email` | Yes |
| `password` | string | `@Size(min=6, max=30)` | Yes |

**Response 200 (OK):** AuthResponse (same schema as signup)

Also sets `refreshToken` as an HttpOnly cookie.

**Response 401 (Unauthorized):**

```json
{ "message": "Invalid email or password" }
```

**Response 403 (Forbidden):**

```json
{ "message": "Account is locked. Please contact administrator." }
```

**curl Example:**

```bash
curl -X POST http://localhost:8080/auth/signin \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "user@example.com",
    "password": "secret123"
  }'
```

---

### 3. POST /auth/refresh

Refresh the access token using the refresh token cookie. Implements token rotation.

**Request Body:** None (reads `refreshToken` from HttpOnly cookie)

**Response 200 (OK):** AuthResponse (same schema as signup)

Also rotates the refresh token cookie (old cookie replaced with new one).

**Response 401 (Unauthorized):**

```json
{ "message": "Session expired. Please login again." }
```

**curl Example:**

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -c cookies.txt
```

---

### 4. POST /auth/logout

Logout the current session. Revokes the current refresh token.

**Request Body:** None (reads `refreshToken` from cookie)

**Response 200 (OK):**

```json
{ "message": "Logged out successfully" }
```

Clears the `refreshToken` cookie.

**curl Example:**

```bash
curl -X POST http://localhost:8080/auth/logout \
  -b cookies.txt \
  -c cookies.txt
```

---

### 5. POST /auth/logout-all

Logout from all devices. Revokes all refresh tokens for the current user.

**Request Body:** None

**Response 200 (OK):**

```json
{ "message": "Logged out from all devices" }
```

Clears the `refreshToken` cookie and revokes all user sessions.

---

## User Endpoints (Authenticated)

**Base path:** `/api/user`
**Authentication:** Bearer token (any authenticated user)

---

### 6. GET /api/user/profile

Get the currently authenticated user's profile.

**Response 200 (OK):** UserDTO

```json
{
  "id": 1,
  "email": "user@example.com",
  "phone": "+1234567890",
  "provider": "LOCAL",
  "emailVerified": true,
  "roleName": "ROLE_CUSTOMER",
  "isLocked": false,
  "createdAt": "2025-01-15T10:30:00Z",
  "modifiedAt": "2025-01-15T10:30:00Z",
  "imageUrl": "https://example.com/avatar.png"
}
```

**UserDTO Fields:**

| Field | Type | Description |
|---|---|---|
| `id` | int | User ID |
| `email` | string | Email address |
| `phone` | string | Phone number (nullable) |
| `provider` | string | Auth provider: `LOCAL`, `GOOGLE`, `GITHUB`, `FACEBOOK` |
| `emailVerified` | boolean | Whether email is verified |
| `roleName` | string | Assigned role name |
| `isLocked` | boolean | Whether account is locked |
| `createdAt` | timestamp | Account creation time |
| `modifiedAt` | timestamp | Last modification time |
| `imageUrl` | string | Profile image URL (nullable) |

---

### 7. GET /api/user/sessions

Get all active sessions for the current user.

**Response 200 (OK):** Array of SessionDTO

```json
[
  {
    "sessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "deviceId": "device-fingerprint-string",
    "ipAddress": "192.168.1.100",
    "userAgent": "Chrome 120 on Windows 10",
    "issuedAt": "2025-01-15T10:30:00Z",
    "lastUsedAt": "2025-01-15T11:00:00Z",
    "expiresAt": "2025-01-22T10:30:00Z",
    "isCurrentSession": true
  }
]
```

**SessionDTO Fields:**

| Field | Type | Description |
|---|---|---|
| `sessionId` | string (UUID) | Unique session identifier |
| `deviceId` | string | Device fingerprint |
| `ipAddress` | string | IP address of the session |
| `userAgent` | string | Parsed user-agent string |
| `issuedAt` | instant | When the session was created |
| `lastUsedAt` | instant | When the session was last used |
| `expiresAt` | instant | When the session expires |
| `isCurrentSession` | boolean | Whether this is the requesting session |

---

### 8. DELETE /api/user/sessions/{sessionId}

Revoke a specific session belonging to the current user.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `sessionId` | string (UUID) | The session ID to revoke |

**Response 200 (OK):**

```json
{ "message": "Session revoked successfully" }
```

If revoking the current session, the `refreshToken` cookie is also cleared.

**Response 400 (Bad Request):**

```json
{ "message": "Session already revoked" }
```

**Response 404 (Not Found):** If session not found or does not belong to the current user.

---

### 9. DELETE /api/user/sessions/other

Revoke all sessions except the current one.

**Response 200 (OK):**

```json
{ "message": "Revoked N other session(s)" }
```

---

## Admin Endpoints (ROLE_ADMIN)

**Base path:** `/api/admin`
**Authentication:** Bearer token with `ROLE_ADMIN`

---

### User Management

---

### 10. GET /api/admin/users

List all users in the system.

**Response 200 (OK):** Array of UserDTO

```json
[
  {
    "id": 1,
    "email": "admin@example.com",
    "phone": null,
    "provider": "LOCAL",
    "emailVerified": true,
    "roleName": "ROLE_ADMIN",
    "isLocked": false,
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "imageUrl": null
  }
]
```

---

### 11. GET /api/admin/users/{id}

Get a specific user by ID.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `id` | int | Positive integer | User ID |

**Response 200 (OK):** UserDTO

**Response 404 (Not Found):** If user does not exist.

---

### 12. POST /api/admin/users

Create a new user (admin-created).

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `email` | string | `@Email` | Yes | Email address |
| `password` | string | `@Size(min=6, max=30)` | Yes | User password |
| `phone` | string | `@Size(max=20)` | No | Phone number |
| `roleId` | int | — | No | Role ID to assign |
| `isLocked` | boolean | — | No | Whether account is locked |

**Response 201 (Created):** UserDTO

**Response 400 (Bad Request):**

```json
{ "message": "Email already exists" }
```

**curl Example:**

```bash
curl -X POST http://localhost:8080/api/admin/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_access_token>" \
  -d '{
    "email": "newemployee@example.com",
    "password": "tempPass123",
    "phone": "+1234567890",
    "roleId": 2,
    "isLocked": false
  }'
```

---

### 13. PUT /api/admin/users/{id}

Update an existing user. All fields are optional; only provided fields are updated.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `id` | int | Positive integer | User ID |

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `email` | string | `@Email` | No | New email address |
| `password` | string | `@Size(min=6, max=30)` | No | New password |
| `phone` | string | `@Size(max=20)` | No | New phone number |
| `roleId` | int | — | No | New role ID |
| `isLocked` | boolean | — | No | Lock/unlock account |

**Response 200 (OK):** UserDTO

**Response 400 (Bad Request):**

```json
{ "message": "Email already exists" }
```

**Response 404 (Not Found):** If user does not exist.

---

### 14. DELETE /api/admin/users/{id}

Delete a user.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `id` | int | Positive integer | User ID |

**Response 200 (OK):**

```json
{ "message": "User deleted successfully" }
```

**Response 404 (Not Found):** If user does not exist.

---

### Role Management

---

### 15. GET /api/admin/roles

List all roles.

**Response 200 (OK):** Array of Role objects

```json
[
  {
    "id": 1,
    "name": "ROLE_CUSTOMER",
    "description": "Default customer role",
    "createdAt": "2025-01-01T00:00:00Z",
    "isActive": true,
    "permissions": [
      {
        "id": 1,
        "name": "READ_PROFILE",
        "description": "Can read own profile",
        "createdAt": "2025-01-01T00:00:00Z",
        "isActive": true
      }
    ]
  }
]
```

**Role Object Fields:**

| Field | Type | Description |
|---|---|---|
| `id` | int | Role ID |
| `name` | string | Role name (e.g., `ROLE_CUSTOMER`) |
| `description` | string | Role description (nullable) |
| `createdAt` | timestamp | Creation time |
| `isActive` | boolean | Whether the role is active |
| `permissions` | array | Array of Permission objects assigned to this role |

---

### 16. GET /api/admin/roles/{id}

Get a specific role by ID.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `id` | int | Role ID |

**Response 200 (OK):** Role object

**Response 404 (Not Found):** If role does not exist.

---

### 17. POST /api/admin/roles

Create a new role.

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `name` | string | `@NotBlank @Size(max=100)` | Yes | Role name |
| `description` | string | `@Size(max=255)` | No | Role description |
| `permissionIds` | int[] | — | No | Array of permission IDs to assign |

**Response 201 (Created):** Role object

**Response 400 (Bad Request):**

```json
{ "message": "Role already exists" }
```

---

### 18. PUT /api/admin/roles/{id}

Update an existing role. All fields are optional.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `id` | int | Role ID |

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `name` | string | `@Size(max=100)` | No | New role name |
| `description` | string | `@Size(max=255)` | No | New description |
| `permissionIds` | int[] | — | No | New set of permission IDs |

**Response 200 (OK):** Role object

**Response 400 (Bad Request):**

```json
{ "message": "Role name already exists" }
```

**Response 404 (Not Found):** If role does not exist.

---

### 19. DELETE /api/admin/roles/{id}

Delete a role. Fails if users are still assigned to it.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `id` | int | Role ID |

**Response 200 (OK):**

```json
{ "message": "Role deleted successfully" }
```

**Response 400 (Bad Request):**

```json
{ "message": "Cannot delete role: N users are assigned to this role" }
```

**Response 404 (Not Found):** If role does not exist.

---

### Permission Management

---

### 20. GET /api/admin/permissions

List all permissions.

**Response 200 (OK):** Array of Permission objects

```json
[
  {
    "id": 1,
    "name": "READ_PROFILE",
    "description": "Can read own profile",
    "createdAt": "2025-01-01T00:00:00Z",
    "isActive": true
  }
]
```

**Permission Object Fields:**

| Field | Type | Description |
|---|---|---|
| `id` | int | Permission ID |
| `name` | string | Permission name |
| `description` | string | Permission description (nullable) |
| `createdAt` | timestamp | Creation time |
| `isActive` | boolean | Whether the permission is active |

---

### 21. GET /api/admin/permissions/{id}

Get a specific permission by ID.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `id` | int | Permission ID |

**Response 200 (OK):** Permission object

**Response 404 (Not Found):** If permission does not exist.

---

### 22. POST /api/admin/permissions

Create a new permission.

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `name` | string | `@NotBlank @Size(max=50)` | Yes | Permission name |
| `description` | string | `@Size(max=255)` | No | Permission description |

**Response 201 (Created):** Permission object

**Response 400 (Bad Request):**

```json
{ "message": "Permission already exists" }
```

---

### 23. DELETE /api/admin/permissions/{id}

Delete a permission.

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `id` | int | Permission ID |

**Response 200 (OK):**

```json
{ "message": "Permission deleted successfully" }
```

**Response 404 (Not Found):** If permission does not exist.

---

### Session Management (Admin)

---

### 24. GET /api/admin/sessions

List all active sessions across all users. Admin view includes `userId` and `userEmail` fields.

**Response 200 (OK):** Array of SessionDTO (with additional admin fields)

```json
[
  {
    "sessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "userId": 1,
    "userEmail": "user@example.com",
    "deviceId": "device-fingerprint-string",
    "ipAddress": "192.168.1.100",
    "userAgent": "Chrome 120 on Windows 10",
    "issuedAt": "2025-01-15T10:30:00Z",
    "lastUsedAt": "2025-01-15T11:00:00Z",
    "expiresAt": "2025-01-22T10:30:00Z",
    "isCurrentSession": false
  }
]
```

---

### 25. GET /api/admin/users/{userId}/sessions

List all active sessions for a specific user.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `userId` | int | Positive integer | User ID |

**Response 200 (OK):** Array of SessionDTO

**Response 404 (Not Found):** If user does not exist.

---

### 26. DELETE /api/admin/sessions/{sessionId}

Revoke a specific session (any user's session).

**Path Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `sessionId` | string (UUID) | Session ID to revoke |

**Response 200 (OK):**

```json
{ "message": "Session revoked successfully" }
```

**Response 400 (Bad Request):**

```json
{ "message": "Session already revoked" }
```

**Response 404 (Not Found):** If session does not exist.

---

### 27. DELETE /api/admin/users/{userId}/sessions

Revoke all sessions for a specific user.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `userId` | int | Positive integer | User ID |

**Response 200 (OK):**

```json
{ "message": "All sessions revoked for user" }
```

**Response 404 (Not Found):** If user does not exist.

---

### 28. GET /api/admin/sessions/stats

Get session statistics across the system.

**Response 200 (OK):**

```json
{
  "totalActiveSessions": 42,
  "usersWithActiveSessions": 15,
  "totalUsers": 100
}
```

| Field | Type | Description |
|---|---|---|
| `totalActiveSessions` | long | Total number of active sessions |
| `usersWithActiveSessions` | long | Number of users with at least one active session |
| `totalUsers` | long | Total number of registered users |

---

## Manager Endpoints (ROLE_PLANT_MANAGER or ROLE_ADMIN)

**Base path:** `/api/manager`
**Authentication:** Bearer token with `ROLE_PLANT_MANAGER` or `ROLE_ADMIN`

---

### 29. GET /api/manager/customers

List all customers (users with `ROLE_CUSTOMER`).

**Response 200 (OK):** Array of UserDTO

---

### 30. PUT /api/manager/reset-password/{userId}

Reset a user's password.

**Path Parameters:**

| Parameter | Type | Validation | Description |
|---|---|---|---|
| `userId` | int | Positive integer | Target user ID |

**Request Body:**

| Field | Type | Validation | Required | Description |
|---|---|---|---|---|
| `newPassword` | string | `@NotBlank @Size(min=6, max=30)` | Yes | New password |

**Response 200 (OK):**

```json
{ "message": "Password reset successfully" }
```

**Response 404 (Not Found):** If user does not exist.

---

## OAuth2 Endpoints

**Base path:** `/oauth2`

---

### 31. GET /oauth2/user

Get the current OAuth2 authenticated user's info.

**Authentication:** Bearer token

**Response 200 (OK):** Map with user information

---

### 32. GET /oauth2/redirect

OAuth2 redirect handler (used internally by the OAuth2 flow).

**Response 200 (OK):** Map with redirect message

---

## Test Endpoints

**Base path:** `/test`
**Note:** These endpoints are for development and testing purposes.

---

### 33. GET /test/all

Public test endpoint. No authentication required.

**Response 200 (OK):**

```
This endpoint is available for all
```

---

### 34. GET /test/user

Test endpoint accessible by users.

**Authentication:** `ROLE_USER`, `ROLE_ADMIN`, or `ROLE_MODERATOR`

**Response 200 (OK):**

```
User's Content is here :)
```

---

### 35. GET /test/mod

Test endpoint accessible by moderators.

**Authentication:** `ROLE_ADMIN` or `ROLE_MODERATOR`

**Response 200 (OK):**

```
Mod's Content is here :)
```

---

### 36. GET /test/admin

Test endpoint accessible by admins only.

**Authentication:** `ROLE_ADMIN`

**Response 200 (OK):**

```
Admin's Content is here :)
```

---

## Other Endpoints

---

### 37. GET /greet

Public greeting endpoint. No authentication required.

**Response 200 (OK):**

```
Greetings !
```

---

## Quick Reference: Endpoint Summary

### Public Endpoints (No Auth)

| Method | Path | Description |
|---|---|---|
| POST | `/auth/signup` | Register new user |
| POST | `/auth/signin` | Login |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout current session |
| POST | `/auth/logout-all` | Logout all sessions |
| GET | `/test/all` | Public test endpoint |
| GET | `/greet` | Greeting endpoint |
| GET | `/oauth2/redirect` | OAuth2 redirect handler |

### Authenticated Endpoints (Any Role)

| Method | Path | Description |
|---|---|---|
| GET | `/api/user/profile` | Get current user profile |
| GET | `/api/user/sessions` | List own sessions |
| DELETE | `/api/user/sessions/{sessionId}` | Revoke own session |
| DELETE | `/api/user/sessions/other` | Revoke all other sessions |
| GET | `/oauth2/user` | Get OAuth2 user info |

### Manager Endpoints (ROLE_PLANT_MANAGER / ROLE_ADMIN)

| Method | Path | Description |
|---|---|---|
| GET | `/api/manager/customers` | List all customers |
| PUT | `/api/manager/reset-password/{userId}` | Reset user password |

### Admin Endpoints (ROLE_ADMIN)

| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/users` | List all users |
| GET | `/api/admin/users/{id}` | Get user by ID |
| POST | `/api/admin/users` | Create user |
| PUT | `/api/admin/users/{id}` | Update user |
| DELETE | `/api/admin/users/{id}` | Delete user |
| GET | `/api/admin/roles` | List all roles |
| GET | `/api/admin/roles/{id}` | Get role by ID |
| POST | `/api/admin/roles` | Create role |
| PUT | `/api/admin/roles/{id}` | Update role |
| DELETE | `/api/admin/roles/{id}` | Delete role |
| GET | `/api/admin/permissions` | List all permissions |
| GET | `/api/admin/permissions/{id}` | Get permission by ID |
| POST | `/api/admin/permissions` | Create permission |
| DELETE | `/api/admin/permissions/{id}` | Delete permission |
| GET | `/api/admin/sessions` | List all active sessions |
| GET | `/api/admin/users/{userId}/sessions` | List user's sessions |
| DELETE | `/api/admin/sessions/{sessionId}` | Revoke session |
| DELETE | `/api/admin/users/{userId}/sessions` | Revoke all user sessions |
| GET | `/api/admin/sessions/stats` | Session statistics |

### Test Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| GET | `/test/all` | None | Public test |
| GET | `/test/user` | ROLE_USER / ROLE_ADMIN / ROLE_MODERATOR | User test |
| GET | `/test/mod` | ROLE_ADMIN / ROLE_MODERATOR | Moderator test |
| GET | `/test/admin` | ROLE_ADMIN | Admin test |
