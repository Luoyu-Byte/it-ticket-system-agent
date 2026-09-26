package com.github.luoyubyte.backend;

import com.github.luoyubyte.backend.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
