package com.security.springSecurityJWT.services;

import com.security.springSecurityJWT.models.UserEntity;
import com.security.springSecurityJWT.repositories.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class UserDeatailsImpl implements UserDetailsService
{
    @Autowired
    private IUserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        UserEntity user= userRepository.findByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("User not found"+username));

        Collection<? extends GrantedAuthority> authorities=user.getRoles().stream()
                .map(role->new SimpleGrantedAuthority("ROLE_".concat(role.getName().name())))
                .collect(Collectors.toSet());

        return new User(user.getUsername(),user.getPassword(),
                true,//esta activo
                true,//expira la cuenta
                true,//expiran
                true,//se bloquea
                authorities);
    }
}
