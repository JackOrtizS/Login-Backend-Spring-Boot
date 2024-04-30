package com.jackdev.Jwt.JwtConfig;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Inyección de dependencias
    private final JwtService jwtService;           // Servicio para operaciones con JWT
    private final UserDetailsService userDetailsService;  // Servicio para cargar detalles del usuario

    // Método para filtrar las peticiones
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Obtiene el token JWT del encabezado de la solicitud
        final String token = getTokenFromRequest(request);
        final String username;

        // Si no hay token, continúa con el siguiente filtro
        if (token == null) {
            filterChain.doFilter(request, response);
            return;

        }

        // Obtiene el nombre de usuario desde el token JWT
        username = jwtService.getUsernameFromToken(token);

        // Verifica si el usuario no está autenticado y el token es válido
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Carga los detalles del usuario usando el nombre de usuario
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Verifica si el token es válido para el usuario
            if (jwtService.isTokenValid(token, userDetails)) {

                // Crea un objeto de autenticación con el nombre de usuario, detalles nulos y roles del usuario
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        userDetails.getAuthorities());

                // Agrega detalles de autenticación basados en la solicitud
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Establece la autenticación en el contexto de seguridad
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        // Continúa con el siguiente filtro en la cadena
        filterChain.doFilter(request, response);
    }

    // Método para obtener el token JWT del encabezado Authorization
    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Verifica si el encabezado Authorization comienza con "Bearer "
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Retorna el token JWT sin el prefijo "Bearer "
        }
        return null;
    }

}
