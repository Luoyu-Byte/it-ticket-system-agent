package com.github.luoyubyte.backend.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Select("SELECT  COUNT(*) FROM sys_user")
    long countUsers();
}
