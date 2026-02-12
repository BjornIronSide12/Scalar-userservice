package dev.naman.userservicetestfinal.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringSecurity {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(
//                authorize -> authorize.requestMatchers("/auth/login").authenticated()
//        );
//        http.authorizeHttpRequests(
//                authorize -> authorize.requestMatchers("/auth/users").authenticated()
//        );
        http.cors().disable();
        http.csrf().disable();
        http.authorizeHttpRequests(
                authorizeRequests ->
                        authorizeRequests.anyRequest().permitAll());

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
