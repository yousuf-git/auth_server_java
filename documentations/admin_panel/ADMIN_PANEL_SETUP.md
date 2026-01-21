# Admin Panel Setup Guide

## Overview
This admin panel provides three different user interfaces based on user roles:
1. **Customer Dashboard** - Minimal view-only interface for customers
2. **Plant Manager Panel** - Customer management and password reset capabilities
3. **Admin Panel** - Full system management (users, roles, permissions)

## Technology Stack
- **Frontend**: HTML + Tailwind CSS (CDN)
- **Backend**: Spring Boot REST APIs
- **Authentication**: JWT-based

## Setup Instructions

### 1. Run Database Migration
First, apply the database schema changes:
```bash
psql -U postgres -d your_database -f database_migration_refactor.sql
```

### 2. Insert Initial Data
Create default roles, permissions, and test users:
```bash
psql -U postgres -d your_database -f initial_admin_data.sql
```

### 3. Start the Application
```bash
mvn spring-boot:run
```

### 4. Access the Admin Panel
Open your browser and navigate to:
```
http://localhost:8080/login.html
```

## Default Test Users

| Email | Password | Role | Access Level |
|-------|----------|------|--------------|
| admin@example.com | admin123 | ROLE_ADMIN | Full system access |
| manager@example.com | manager123 | ROLE_PLANT_MANAGER | View customers, reset passwords |
| customer@example.com | customer123 | ROLE_CUSTOMER | View own profile only |

**⚠️ IMPORTANT**: Change these default passwords immediately after first login in production!

## API Endpoints

### Authentication
- `POST /auth/signin` - Login with email and password
- `POST /auth/signup` - Register new user

### User Profile
- `GET /api/user/profile` - Get current user profile

### Plant Manager APIs (Requires ROLE_PLANT_MANAGER or ROLE_ADMIN)
- `GET /api/manager/customers` - List all customers
- `PUT /api/manager/reset-password/{userId}` - Reset user password

### Admin APIs (Requires ROLE_ADMIN)

#### User Management
- `GET /api/admin/users` - List all users
- `GET /api/admin/users/{id}` - Get user by ID
- `POST /api/admin/users` - Create new user
- `PUT /api/admin/users/{id}` - Update user
- `DELETE /api/admin/users/{id}` - Delete user

#### Role Management
- `GET /api/admin/roles` - List all roles
- `GET /api/admin/roles/{id}` - Get role by ID
- `POST /api/admin/roles` - Create new role
- `PUT /api/admin/roles/{id}` - Update role
- `DELETE /api/admin/roles/{id}` - Delete role

#### Permission Management
- `GET /api/admin/permissions` - List all permissions
- `GET /api/admin/permissions/{id}` - Get permission by ID
- `POST /api/admin/permissions` - Create new permission
- `DELETE /api/admin/permissions/{id}` - Delete permission

## Pages Description

### 1. Login Page (`login.html`)
- Email and password authentication
- Redirects users to appropriate dashboard based on role
- Stores JWT token in localStorage

### 2. Customer Dashboard (`customer-dashboard.html`)
- **Access**: Any authenticated user
- **Features**:
  - View profile picture and name
  - Display email, phone, role, verification status
  - View account status (active/locked)
  - Read-only interface - no controls available
  - Logout functionality

### 3. Plant Manager Panel (`manager-panel.html`)
- **Access**: ROLE_PLANT_MANAGER or ROLE_ADMIN
- **Features**:
  - View all customers in a table
  - Search customers by email or phone
  - View customer details (email, phone, role, status)
  - Reset customer passwords
  - Logout functionality

### 4. Admin Panel (`admin-panel.html`)
- **Access**: ROLE_ADMIN only
- **Features**:
  
  **Users Tab**:
  - List all users with full details
  - Create new users
  - Edit existing users (email, phone, password, role, lock status)
  - Delete users
  
  **Roles Tab**:
  - List all roles with their permissions
  - Create new roles
  - Edit roles and assign permissions
  - Delete roles (with user count validation)
  
  **Permissions Tab**:
  - List all permissions
  - Create new permissions
  - Delete permissions

## Security Features

### JWT Authentication
- All API requests (except auth endpoints) require JWT token
- Token stored in localStorage
- Token sent via Authorization header: `Bearer <token>`
- Automatic logout on 401 Unauthorized

### Role-Based Access Control
- Customer: Can only view own profile
- Plant Manager: Can view customers and reset passwords
- Admin: Full CRUD access to users, roles, and permissions

### Password Security
- All passwords are hashed using BCrypt
- Minimum password length: 6 characters
- Password reset requires manager or admin role

## Frontend Architecture

### State Management
- JWT token stored in localStorage
- User info cached in localStorage after login
- Automatic token validation on page load

### API Communication
- Fetch API for HTTP requests
- Authorization header with Bearer token
- Error handling with user-friendly messages
- Loading states for better UX

### Styling
- Tailwind CSS via CDN (no build step required)
- Responsive design for mobile and desktop
- Consistent color scheme (indigo/blue)
- Modal dialogs for forms
- Toast notifications for feedback

## Customization

### Changing Colors
Edit the Tailwind classes in HTML files:
- Primary: `bg-indigo-600` → `bg-blue-600`
- Success: `text-green-600` → `text-emerald-600`
- Error: `text-red-600` → `text-rose-600`

### Adding New Permissions
1. Insert into database:
```sql
INSERT INTO permissions (name, description, is_active) 
VALUES ('CUSTOM_PERMISSION', 'Description', true);
```
2. Assign to roles via Admin Panel

### Adding New Roles
1. Use Admin Panel > Roles tab > Create Role
2. Assign appropriate permissions
3. Create users with new role

## Troubleshooting

### Cannot Login
- Check database connection
- Verify user exists: `SELECT * FROM users WHERE email = 'your@email.com';`
- Verify password encoding is BCrypt
- Check application logs for authentication errors

### 403 Forbidden on API Calls
- Verify JWT token is valid
- Check user has required role
- Review Spring Security configuration in `WebSecurityConfig.java`

### Static Files Not Loading
- Verify files are in `src/main/resources/static/`
- Check WebSecurityConfig permits HTML files
- Clear browser cache

### CORS Issues
- Admin panel should work on same origin
- If using different port, add CORS configuration

## Production Deployment

### Security Checklist
- [ ] Change all default passwords
- [ ] Use HTTPS for all connections
- [ ] Set strong JWT secret in application.yml
- [ ] Enable CSRF for state-changing operations
- [ ] Configure proper CORS policies
- [ ] Implement rate limiting
- [ ] Add password complexity requirements
- [ ] Enable account lockout after failed attempts
- [ ] Implement audit logging
- [ ] Regular security updates

### Environment Variables
Set these in production:
```bash
SPRING_PROFILES_ACTIVE=prod
JWT_SECRET=your-secure-secret-key-here
DATABASE_URL=your-production-db-url
```

## Support
For issues or questions, refer to the main project documentation.
