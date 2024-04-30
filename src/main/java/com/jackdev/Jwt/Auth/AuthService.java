package com.jackdev.Jwt.Auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jackdev.Jwt.JwtConfig.JwtService;
import com.jackdev.Jwt.User.Role;
import com.jackdev.Jwt.User.User;
import com.jackdev.Jwt.User.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    // Repositorio de usuarios para operaciones CRUD en la base de datos
    private final UserRepository userRepository;
    // Servicio para generar y validar tokens JWT
    private final JwtService jwtService;
    // Codificador de contraseñas para codificar y verificar contraseñas
    private final PasswordEncoder passwordEncoder;
    // Gestor de autenticación de Spring Security para autenticar usuarios
    private final AuthenticationManager authenticationManager;

    // Método para iniciar sesión
    public AuthResponse login(LoginRequest request) {
        // Autentica el usuario utilizando el AuthenticationManager
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // Busca el usuario por nombre de usuario y obtiene sus detalles
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();

        // Genera un token JWT para el usuario
        String token = jwtService.getToken(user);

        // Construye y devuelve una respuesta con el token JWT
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    // Método para registrar un nuevo usuario
    public AuthResponse register(RegisterRequest request) {

        // Crea un nuevo usuario con los datos proporcionados en la solicitud
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword())) // Codifica la contraseña antes de almacenarla
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .country(request.getCountry())
                .role(Role.USER) // Asigna el rol USER al nuevo usuario
                .build();

        // Guarda el nuevo usuario en la base de datos
        userRepository.save(user);

        // Construye y devuelve una respuesta con el token JWT
        return AuthResponse.builder()
                .token(jwtService.getToken(user))
                .build();
    }

}
