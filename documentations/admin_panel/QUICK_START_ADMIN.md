# Quick Start Guide - Admin Panel

## Prerequisites
- PostgreSQL database running
- Java 21+ installed
- Maven installed

## Quick Setup (5 minutes)

### Step 1: Database Setup
```bash
# Run the migration first
psql -U postgres -d your_database -f database_migration_refactor.sql

# Insert initial data (roles, permissions, test users)
psql -U postgres -d your_database -f initial_admin_data.sql
```

### Step 2: Start Application
```bash
mvn spring-boot:run
```

### Step 3: Access Admin Panel
Open browser: http://localhost:8080

## Test Accounts

### Admin Access (Full Control)
- Email: `admin@example.com`
- Password: `admin123`
- Can: Manage all users, roles, and permissions

### Plant Manager Access
- Email: `manager@example.com`
- Password: `manager123`
- Can: View customers and reset passwords

### Customer Access (Read-Only)
- Email: `customer@example.com`
- Password: `customer123`
- Can: View own profile only

## What You Can Do

### As Admin
1. **Users Tab**: Create, edit, delete users
2. **Roles Tab**: Create roles, assign permissions
3. **Permissions Tab**: Create new permissions

### As Plant Manager
- View all customers in a table
- Search by email or phone
- Reset customer passwords

### As Customer
- View profile information (read-only)
- See account status

## Files Created

### HTML Pages (in `src/main/resources/static/`)
- `login.html` - Login page
- `customer-dashboard.html` - Customer view
- `manager-panel.html` - Manager view
- `admin-panel.html` - Admin view
- `index.html` - Redirects to login

### Backend Controllers (in `src/main/java/.../controllers/`)
- `UserController.java` - User profile API
- `ManagerController.java` - Manager operations
- `AdminController.java` - Admin operations

### Documentation
- `ADMIN_PANEL_SETUP.md` - Full documentation
- `initial_admin_data.sql` - Initial data script

## API Examples

### Login
```bash
curl -X POST http://localhost:8080/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

### Get Users (Admin)
```bash
curl http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create Role (Admin)
```bash
curl -X POST http://localhost:8080/api/admin/roles \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ROLE_SUPERVISOR",
    "description": "Supervisor role",
    "permissionIds": [1, 2, 3]
  }'
```

## Troubleshooting

### Cannot login?
- Check database is running
- Verify initial data was inserted
- Check application logs

### 403 Forbidden?
- Verify JWT token is valid
- Check user has correct role
- Token expires after configured time

### Pages not loading?
- Verify static files in `src/main/resources/static/`
- Check WebSecurityConfig permits HTML files
- Clear browser cache

## Next Steps

1. ✅ Test login with all three accounts
2. ✅ Create a new role via Admin Panel
3. ✅ Create a new user and assign role
4. ✅ Test manager password reset functionality
5. ⚠️ **CHANGE DEFAULT PASSWORDS** in production!

## Production Checklist

Before deploying to production:
- [ ] Change all default passwords
- [ ] Use HTTPS
- [ ] Set strong JWT secret
- [ ] Configure CORS properly
- [ ] Enable CSRF protection
- [ ] Set up rate limiting
- [ ] Implement audit logging
- [ ] Regular backups

## Support

For detailed documentation, see `ADMIN_PANEL_SETUP.md`
