package com.github.luoyubyte.backend.service;

import com.github.luoyubyte.backend.mapper.UserMapper;
import com.github.luoyubyte.backend.security.TemporaryPasswordGenerator;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

//确认系统允许初始化，然后创建第一个管理员，并把临时登录凭据交给初始化入口。
@Service
public class InitialAdminService {
    private static final String INITIAL_EMPLOYEE_NO = "INIT_ADMIN";

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final TemporaryPasswordGenerator passwordGenerator;

    public InitialAdminService(
            UserMapper userMapper,
            PasswordEncoder passwordEncoder,
            TemporaryPasswordGenerator passwordGenerator
    ) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.passwordGenerator = passwordGenerator;
    }

    // synchronized 只负责当前实例内串行执行。
    // 多实例同时初始化，仍依赖固定工号的数据库唯一约束兜底。
    public synchronized InitialAdminCredentials initialize(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("管理员姓名不能为空");
        }

        String normalizedName = name.strip();

        if (normalizedName.codePointCount(0, normalizedName.length()) > 50) {
            throw new IllegalArgumentException("管理员姓名不能超过50个字符");
        }

        // 已有管理员，包括已停用管理员，都不能重新初始化。
        if (userMapper.countAdmins() > 0) {
            throw new IllegalStateException("系统已有管理员，不能重复初始化");
        }

        // 初始工号若被其他账号占用，也不能覆盖或擅自升级其角色。
        if (userMapper.findByEmployeeNo(INITIAL_EMPLOYEE_NO) != null) {
            throw new IllegalStateException("初始管理员工号已被占用");
        }

        // 临时密码仅用于本次交付，数据库只保存编码后的哈希。
        String temporaryPassword = passwordGenerator.generate();
        String passwordHash = passwordEncoder.encode(temporaryPassword);

        int affectedRows;
        // 【核心：创建账号】调用 Mapper 执行 INSERT，成功后账号已写入数据库。
        try {
            affectedRows = userMapper.insertInitialAdmin(
                    INITIAL_EMPLOYEE_NO,
                    normalizedName,
                    passwordHash
            );
        } catch (DuplicateKeyException exception) {
            // 检查后仍可能发生并发插入，不能捕获后改成覆盖更新。
            throw new IllegalStateException(
                    "初始管理员工号已被占用，初始化未覆盖任何账号"
            );
        }

        if (affectedRows != 1) {
            throw new IllegalStateException("初始管理员创建结果异常，请核查");
        }

        // 仅交给后续本机初始化入口，不作为公开HTTP响应或日志输出。
        return new InitialAdminCredentials(
                INITIAL_EMPLOYEE_NO,
                temporaryPassword
        );


    }

    public record InitialAdminCredentials(
            String employeeNo,
            String temporaryPassword
    ) {
        // 防止打印整个结果对象时泄露临时密码。
        @Override
        public String toString() {
            return "InitialAdminCredentials[PROTECTED]";
        }
    }
}