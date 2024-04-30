package com.jackdev.Jwt.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jackdev.Jwt.User.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    // Inyección del repositorio de usuarios
    private final UserRepository userRepository;

    // Define el bean para el AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // Obtiene el AuthenticationManager de AuthenticationConfiguration
        return config.getAuthenticationManager();
    }

    // Define el bean para el AuthenticationProvider
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // Crea un DaoAuthenticationProvider
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

        // Configura el UserDetailsService
        authenticationProvider.setUserDetailsService(userDetailService());

        // Configura el PasswordEncoder
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    // Define el bean para el PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Crea y devuelve un BCryptPasswordEncoder
        return new BCryptPasswordEncoder();
    }

    // Define el bean para el UserDetailsService personalizado
    @Bean
    public UserDetailsService userDetailService() {
        // Implementa un UserDetailsService personalizado que utiliza UserRepository
        return username -> userRepository.findByUsername(username)
                // Si no se encuentra el usuario, lanza una excepción UsernameNotFoundException
                .orElseThrow(() -> new UsernameNotFoundException("User not fournd"));
    }
}
