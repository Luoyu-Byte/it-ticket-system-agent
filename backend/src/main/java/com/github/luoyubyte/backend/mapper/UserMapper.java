package com.github.luoyubyte.backend.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import com.github.luoyubyte.backend.entity.SysUser;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Update;

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
