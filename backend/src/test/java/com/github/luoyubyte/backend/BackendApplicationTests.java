package com.github.luoyubyte.backend;

import com.github.luoyubyte.backend.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;
import com.github.luoyubyte.backend.entity.SysUser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@SpringBootTest
class BackendApplicationTests {

    @Autowired
    private UserMapper userMapper;

    @Test
    void contextLoads() {
    }

    @Test
    void shouldCountUsers() {
        long count = userMapper.countUsers();

        System.out.println("当前账号数量：" + count);

        assertTrue(count >= 0, "账号数量不能小于 0");
    }
    @Test
    void shouldFindUserByEmployeeNo() {
        SysUser user = userMapper.findByEmployeeNo("TEST_QUERY_001");

        assertNotNull(user, "应查到预先准备的测试账号");

        assertNotNull(user.getId());
        assertTrue(user.getId() > 0);
        assertEquals("TEST_QUERY_001", user.getEmployeeNo());
        assertEquals("映射测试员工", user.getName());
        assertEquals("TEST_ONLY_NOT_A_REAL_HASH", user.getPasswordHash());
        assertEquals("EMPLOYEE", user.getRole());
        assertEquals("ACTIVE", user.getStatus());
        assertEquals(Boolean.TRUE, user.getMustChangePassword());
        assertNotNull(user.getCreatedAt());
        assertEquals("mapper-test@example.com", user.getEmail());
    }

    @Test
    void shouldReturnNullWhenUserDoesNotExist() {
        SysUser user = userMapper.findByEmployeeNo("TEST_QUERY_NOT_EXISTS");

        assertNull(user, "不存在的工号应返回 null");
    }
}
