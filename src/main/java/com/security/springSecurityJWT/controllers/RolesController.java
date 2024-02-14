package com.security.springSecurityJWT.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RolesController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/accessAdmin")
    public String accessAdmin(){
        return "Admin";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/accesuer")
    public String accesuer(){
        return "access user";
    }
    @PreAuthorize("hasRole('INVITED')")
    @GetMapping("/accessinvited")
    public String accessinvited(){
        return "access invited";
    }
}
