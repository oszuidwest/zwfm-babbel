-- Development and test login: admin/admin. Never load this file in production.
INSERT INTO users (username, full_name, password_hash, email, role, password_changed_at) VALUES
('admin', 'System Administrator', '$2a$10$9JLNLD7JuNuTyhsgFQlXNevfypkWJ8XLBtZcbHyJf6XB8.1DAw5gy', 'admin@babbel.local', 'admin', CURRENT_TIMESTAMP);
