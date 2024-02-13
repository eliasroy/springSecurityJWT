package com.security.springSecurityJWT.security;

import com.security.springSecurityJWT.security.filters.JwtAthorizationFilter;
import com.security.springSecurityJWT.security.filters.JwtAuthenticationFilter;
import com.security.springSecurityJWT.security.jwt.JwtUtils;
import com.security.springSecurityJWT.services.UserDeatailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig
{
    @Autowired
    JwtUtils jwtutils;
    @Autowired
    UserDeatailsImpl userDetailsService;
    @Autowired
    JwtAthorizationFilter jwtAthorizationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,AuthenticationManager athenticationManager) throws Exception{
        JwtAuthenticationFilter jwtAuthenticationFilter=new JwtAuthenticationFilter(jwtutils);
        jwtAuthenticationFilter.setAuthenticationManager(athenticationManager);
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(config->{
                    config.requestMatchers("/hello").permitAll();
                    config.anyRequest().authenticated();})
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilter(jwtAuthenticationFilter)
                .addFilterBefore(jwtAthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder) throws Exception {
         http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);

         return http.getSharedObject(AuthenticationManagerBuilder.class).build();

    }



}
