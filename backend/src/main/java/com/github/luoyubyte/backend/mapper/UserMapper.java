package com.github.luoyubyte.backend.mapper;

import org.apache.ibatis.annotations.*;
import com.github.luoyubyte.backend.entity.SysUser;

@Mapper
public interface UserMapper {

    @Select("SELECT COUNT(*) FROM sys_user")
    long countUsers();

    //统计所有管理员，包括已停用的管理员
    //管理员被停用不代表系统从未初始化，不能借此重新创建管理员
    @Select("""
        SELECT COUNT(*)
        FROM sys_user
        WHERE role='ADMIN'
""")
    long countAdmins();
    // 只用于创建初始管理员，角色、状态和强制改密标记固定。
    // 密码必须先由业务层编码，这里只接收哈希，不接收明文。
    // 不使用覆盖更新：工号重复时由数据库拒绝，不能覆盖已有账号。
    @Insert("""
    INSERT INTO sys_user(employee_no, name, password_hash,
                                  role, status, must_change_password)
    VALUES (#{employeeNo}, #{name}, #{passwordHash},
                     'ADMIN', 'ACTIVE', TRUE)
""")
    int insertInitialAdmin(
            @Param("employeeNo") String employeeNo,
            @Param("name") String name,
            @Param("passwordHash") String passwordHash
    );

    @Select("""
        SELECT id,
               employee_no AS employeeNo,
               name,
               password_hash AS passwordHash,
               role,
               status,
               must_change_password AS mustChangePassword,
               created_at AS createdAt,
               email
        FROM sys_user
        WHERE employee_no = #{employeeNo}
        """)
    SysUser findByEmployeeNo(
            @Param("employeeNo") String employeeNo

    );
    @Update(""" 
        UPDATE sys_user
        SET password_hash =#{newPasswordHash},
            must_change_password = FALSE
        WHERE id =#{id}
            AND status ='ACTIVE'
            AND CAST(password_hash AS BINARY)
        =CAST(#{expectedPasswordHash} AS BINARY)
""")
    int updatePassword(
            @Param("id") Long id,
            @Param("expectedPasswordHash") String expectedPasswordHash,
            @Param("newPasswordHash") String newPasswordHash
    );
}
