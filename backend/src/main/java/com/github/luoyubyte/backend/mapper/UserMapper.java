package com.github.luoyubyte.backend.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import com.github.luoyubyte.backend.entity.SysUser;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper {

    @Select("SELECT COUNT(*) FROM sys_user")
    long countUsers();

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
    SysUser findByEmployeeNo(@Param("employeeNo") String employeeNo);
}
