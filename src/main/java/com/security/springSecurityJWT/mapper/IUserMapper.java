package com.security.springSecurityJWT.mapper;

import com.security.springSecurityJWT.models.UserEntity;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

@Mapper
public interface IUserMapper {

    @Select("SELECT * FROM USERS WHERE USERNAME=#{username}")
    Optional<UserEntity> findByUsername(String username);

    @Insert("INSERT INTO USERS (USERNAME, EMAIL, PASSWORD) VALUES (#{USERNAME}, #{EMAIL}, #{PASSWORD})")
    void save(UserEntity userEntity);


    @Delete("DELETE FROM USERS WHERE ID=#{ID}")
    void deleteById(Long ID);

    @Select("SELECT * FROM USERS")
    List<UserEntity> findAll();
}
