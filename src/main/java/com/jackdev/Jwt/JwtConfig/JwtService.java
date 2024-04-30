package com.jackdev.Jwt.JwtConfig;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    // Clave secreta para firmar y verificar tokens JWT
    private static final String SECRET_KEY = "586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    // Método para generar un token JWT para un UserDetails dado
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    // Método privado para generar un token JWT con reclamaciones adicionales
    private String getToken(Map<String, Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)                // Define reclamaciones adicionales
                .setSubject(user.getUsername())         // Define el sujeto del token como el nombre de usuario
                .setIssuedAt(new Date(System.currentTimeMillis()))  // Define la fecha de emisión del token
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))  // Define la fecha de expiración del token (24 horas)
                .signWith(getKey(), SignatureAlgorithm.HS256)  // Firma el token con el algoritmo HS256 y la clave secreta
                .compact();
    }

    // Método para obtener la clave secreta como un objeto Key
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);  // Decodifica la clave secreta de Base64
        return Keys.hmacShaKeyFor(keyBytes);  // Crea una clave HMAC a partir de los bytes decodificados

    }

    // Método para obtener el nombre de usuario desde un token JWT
    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    // Método para verificar si un token es válido para un UserDetails dado
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Método para obtener todas las reclamaciones de un token JWT
    private Claims getAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())  // Define la clave secreta para verificar la firma del token
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Método genérico para obtener una reclamación específica de un token JWT
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Método privado para obtener la fecha de expiración de un token JWT
    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    // Método privado para verificar si un token JWT ha expirado
    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }
}
