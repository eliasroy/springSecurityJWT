package com.security.springSecurityJWT.security.filters;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.springSecurityJWT.models.UserEntity;
import com.security.springSecurityJWT.security.jwt.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils){
        this.jwtUtils=jwtUtils;
    }
    //intenta autenticar el usuario y devuelve un objeto de tipo Authentication
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UserEntity  user = null;
        String username="";
        String password="";
        try {
            //aqui el objeto json que viene del login lo coloca en la clase userEntity
            user=new ObjectMapper().readValue(request.getInputStream(),UserEntity.class);
            username=user.getUsername();
            password=user.getPassword();
        }catch (StreamReadException e) {
            throw new RuntimeException(e);
        } catch (DatabindException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //aqu se autentica en la aplicacion;cuand sale oto correcto va al metodo successfulAuthentication
        UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,password);
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user=(User) authResult.getPrincipal();
        String token= jwtUtils.generateAccessToken(user.getUsername());

        response.addHeader("Authorization", "Bearer "+token);
        Map<String, Object> httpResponse= new HashMap<>();
        httpResponse.put("token", token);
        httpResponse.put("Message", "Authenticacion correcta");
        httpResponse.put("Username", user.getUsername());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush();//que se escriba todo correcto
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
