package tn.isims.springSecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tn.isims.springSecurity.security.jwt.AuthEntryPointJwt;
import tn.isims.springSecurity.security.jwt.AuthTokenFilter;
import tn.isims.springSecurity.security.services.UserDetailsServiceImpl;

/**
 * Configuration de la sécurité web de l'application.
 * Cette classe configure la sécurité web en utilisant Spring Security, en définissant les règles d'authentification,
 * les filtres de sécurité et les encodeurs de mot de passe.
 */
@Configuration
@EnableMethodSecurity // Active la sécurité des méthodes, permettant l'utilisation des annotations comme @Secured et @PreAuthorize
public class WebSecurityConfig { // extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsServiceImpl userDetailsService; // Service de détails utilisateur pour l'authentification

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler; // Gestionnaire des erreurs d'authentification

    /**
     * Crée un bean pour le filtre d'authentification JWT.
     * Ce filtre est utilisé pour valider les tokens JWT dans les requêtes entrantes.
     *
     * @return un nouvel objet AuthTokenFilter.
     */
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    /**
     * Crée un bean pour le fournisseur d'authentification.
     * Ce fournisseur utilise le service de détails utilisateur et l'encodeur de mot de passe pour l'authentification.
     *
     * @return un nouvel objet DaoAuthenticationProvider configuré.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService); // Définit le service de détails utilisateur
        authProvider.setPasswordEncoder(passwordEncoder()); // Définit l'encodeur de mot de passe

        return authProvider;
    }

//  @Bean
//  @Override
//  public AuthenticationManager authenticationManagerBean() throws Exception {
//    return super.authenticationManagerBean();
//  }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//  @Override
//  protected void configure(HttpSecurity http) throws Exception {
//    http.cors().and().csrf().disable()
//      .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
//      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//      .authorizeRequests().antMatchers("/api/auth/**").permitAll()
//      .antMatchers("/api/test/**").permitAll()
//      .anyRequest().authenticated();
//
//    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
//  }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/auth/**").permitAll()
                                .requestMatchers("/api/test/**").permitAll()
                                .requestMatchers("/swagger-ui/**").permitAll() // Permet l'accès à Swagger UI sans authentification
                                .requestMatchers("/v3/api-docs/**").permitAll()
                                .anyRequest().authenticated()
                );

        http.authenticationProvider(authenticationProvider());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}