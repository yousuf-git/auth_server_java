---------- Dummy Data Inserstion Script ------------

-- - 1. Permissions

INSERT INTO permission (name, description, is_active) VALUES
('USER_READ', 'Read user information', true),
('USER_WRITE', 'Create and update users', true),
('USER_DELETE', 'Delete users', true),
('ROLE_READ', 'Read role information', true),
('ROLE_WRITE', 'Create and update roles', true),
('ROLE_DELETE', 'Delete roles', true),
('PERMISSION_READ', 'Read permission information', true),
('PERMISSION_WRITE', 'Create and update permissions', true),
('PERMISSION_DELETE', 'Delete permissions', true);

-- - 2. Roles

INSERT INTO role (name, description, is_active) VALUES
('ROLE_CUSTOMER', 'Regular customer with basic access', true),
('ROLE_PLANT_MANAGER', 'Plant manager can view customers and reset passwords', true),
('ROLE_ADMIN', 'Administrator with full system access', true)

-- 3. Associate permissions with roles
Admin gets all permissions

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r
CROSS JOIN permission p
WHERE r.name = 'ROLE_ADMIN';


-- 4. Plant Manager gets read permissions for users
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r, permission p
WHERE r.name = 'ROLE_PLANT_MANAGER'
AND p.name IN ('USER_READ', 'USER_WRITE');

-- 5. Create default admin user
Password: admin123
Note: You should change this password after first login
INSERT INTO users (email, password, phone, provider, email_verified, is_locked, role_id)
SELECT 
    'admin@example.com',
    '$2b$12$EEbZYf2aZMA5D1Fvdg4pBeizduA.RoR/jeGQzohjBBcAjJbD5dzma',  -- BCrypt hash for 'admin123'
    NULL,
    'LOCAL',
    true,
    false,
    r.id
FROM role r
WHERE r.name = 'ROLE_ADMIN';


-- 6. Create default plant manager user
Password: manager123
INSERT INTO users (email, password, phone, provider, email_verified, is_locked, role_id)
SELECT 
    'manager@example.com',
    '$2b$12$NX3ltplMEQKbhvI3zxQVueIsSJfPZVw8/3ImoUv1SMQ0wHQcASYrm',  -- BCrypt hash for 'manager123'
    NULL,
    'LOCAL',
    true,
    false,
    r.id
FROM role r
WHERE r.name = 'ROLE_PLANT_MANAGER';


-- 7. Create default customer user
Password: customer123
INSERT INTO users (email, password, phone, provider, email_verified, is_locked, role_id)
SELECT 
    'customer@example.com',
    '$2b$12$9gn8dwxy8G9mOu2jM/3atuNKIYkMHrA8KMlBw86XTD0TY.9oxn9S2',  -- BCrypt hash for 'customer123'
    '+1234567890',
    'LOCAL',
    true,
    false,
    r.id
FROM role r
WHERE r.name = 'ROLE_CUSTOMER'
ON CONFLICT (email) DO NOTHING;

-- 8. Display count of created data
SELECT 'Permissions Created:' as info, COUNT(*) as count FROM permission;
SELECT 'Roles Created:' as info, COUNT(*) as count FROM role;
SELECT 'Role-Permission Mappings:' as info, COUNT(*) as count FROM role_permission;
SELECT 'Users Created:' as info, COUNT(*) as count FROM users;


-- 9. Display created users
SELECT u.id, u.email, r.name as role, u.is_locked as locked
FROM users u
LEFT JOIN role r ON u.role_id = r.id
ORDER BY u.id;