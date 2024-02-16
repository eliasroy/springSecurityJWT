package com.security.springSecurityJWT.controllers;

import com.security.springSecurityJWT.mapper.IUserMapper;
import com.security.springSecurityJWT.models.ERole;
import com.security.springSecurityJWT.models.RoleEntity;
import com.security.springSecurityJWT.models.UserEntity;
import com.security.springSecurityJWT.models.dtos.UserDTO;
import jakarta.validation.Valid;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@NoArgsConstructor
@Slf4j
public class principalController {
    @Autowired
    private  PasswordEncoder passwordEncoder;

    @Autowired
    private IUserMapper userRepository;
    @GetMapping("/hello")
    public String hello(){
        return "hello world";
    }
    @GetMapping("/hellos")
    public String hellos(){
        return "hello world secured";
    }


    @PostMapping("/createuser")
    public ResponseEntity<?> createUsers(@Valid @RequestBody  UserDTO user){

        Set<RoleEntity> roles=user.getRoles().stream().
                map(role -> RoleEntity.
                        builder()
                        .name(ERole.valueOf(role))
                        .build()).collect(Collectors.toSet());

        log.info("user {}: ".concat(user.toString()));

        UserEntity newuser=UserEntity.builder()
                .username(user.getUsername())
                .password(passwordEncoder.encode(user.getPassword()))
                .email(user.getEmail())
                .roles(roles)
                .build();
        userRepository.save(newuser);
        return ResponseEntity.ok(newuser);

    }

    @DeleteMapping("/deleteuser")
    public String deleteuser(@RequestParam String id){
        userRepository.deleteById(Long.parseLong(id));
        return "user deleted";
    }
    @GetMapping("/getusers")
    public ResponseEntity<?> getusers(){
        return ResponseEntity.ok(userRepository.findAll());
    }
}
