package com.github.luoyubyte.backend.dto;

    //只接收改密所需的字段，不接收用户Id后工号
    //修改seize的密码，又后端根据登录身份确定，不能有前端指定
    public record ChangePasswordRequest(String oldPassword,String newPassword){
        //密码属于敏感数据，避免答应该对象时暴露密码
        @Override
        public String toString(){
            return "ChangePasswordRequest[PROTECTED]";
        }
    }
