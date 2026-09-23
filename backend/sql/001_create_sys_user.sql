CREATE TABLE sys_user(
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    employee_no VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(50) NOT NULL ,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email VARCHAR(254),
    CONSTRAINT chk_sys_user_role
        CHECK (role IN ('EMPLOYEE', 'ENGINEER', 'ADMIN')),
    CONSTRAINT chk_sys_user_status
        CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_sys_user_must_change_password
        CHECK (must_change_password IN (0, 1))
);