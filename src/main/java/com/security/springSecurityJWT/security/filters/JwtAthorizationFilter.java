package com.security.springSecurityJWT.security.filters;

import com.security.springSecurityJWT.security.jwt.JwtUtils;
import com.security.springSecurityJWT.services.UserDeatailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
//valida el token y lo guarda en el contexto de seguridad
@Component
public class JwtAthorizationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtutils;

    @Autowired
    private UserDeatailsImpl userDeatailsImpl;
    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response,
                                    @NotNull FilterChain filterChain) throws ServletException, IOException {

        String token=request.getHeader("Authorization");

        if(token!=null && token.startsWith("Bearer ")){
            token=token.replace("Bearer ","");
            if(jwtutils.validateAccessToken(token))
            {
                String username=jwtutils.getUsername(token);
                UserDetails userDetails=userDeatailsImpl.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authenticationToken=
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                userDetails.getAuthorities()
                        );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response);

    }
}
