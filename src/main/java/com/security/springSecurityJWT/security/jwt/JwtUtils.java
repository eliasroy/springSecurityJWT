package com.security.springSecurityJWT.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtils {
    @Value("${jwt.secret.key}")
    private String secretKey;
    @Value("${jwt.time.expiration}")
    private String timeExpiration;

    // generated acces token
    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(timeExpiration)))
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //validar el token de acceso
    public boolean validateAccessToken(String token) {
        try {

            Jwts.parserBuilder()
                    .setSigningKey(getSecretKey())//valida que el tenga la firma y que sea correcta sino invalida
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return true;
        }catch (Exception e){
            log.error("Error al validar el token de acceso: {} "+ e.getMessage());
            return false;
        }
    }
    //OBTENER EL USERNAME DE TOKEN
    public String getUsername(String token) {
        return getClaim(token, Claims::getSubject); //obtener el subject del token de acceso
    }

    //obtener un solo claim
    public <T> T getClaim(String token, Function<Claims, T> claimsFunction) {
        Claims claim = getClaims(token);
        return claimsFunction.apply(claim);
    }

    //OBTENER EL USUARIO O Claims DEL TOKEN DE ACCESO
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())//valida que el tenga la firma y que sea correcta sino invalida
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //obteer token de acceso
    public Key getSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return  Keys.hmacShaKeyFor(keyBytes);
    }


}
