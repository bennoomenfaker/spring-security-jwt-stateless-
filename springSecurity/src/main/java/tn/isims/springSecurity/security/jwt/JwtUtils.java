package tn.isims.springSecurity.security.jwt;


import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import tn.isims.springSecurity.security.services.UserDetailsImpl;


/**
 * Utilitaire pour la gestion des tokens JWT (JSON Web Tokens).
 * Cette classe fournit des méthodes pour générer, valider et extraire des informations des tokens JWT.
 */
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class); // Logger pour enregistrer les erreurs liées aux JWT

    @Value("${faker.app.jwtSecret}")
    private String jwtSecret; // Clé secrète pour signer les JWT, injectée depuis les propriétés de l'application

    @Value("${faker.app.jwtExpirationMs}")
    private int jwtExpirationMs; // Durée de validité du JWT en millisecondes, injectée depuis les propriétés de l'application

    /**
     * Génère un token JWT à partir de l'objet Authentication.
     * Le token contient le nom d'utilisateur, la date d'émission et la date d'expiration.
     *
     * @param authentication Objet Authentication contenant les détails de l'utilisateur authentifié.
     * @return Le token JWT généré sous forme de chaîne de caractères.
     */
    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal(); // Récupère les détails de l'utilisateur depuis l'objet Authentication

        // Crée et retourne un token JWT signé avec la clé secrète et contenant les informations de l'utilisateur
        return Jwts.builder()
                .setSubject(userPrincipal.getEmail()) // Définit le sujet du token (nom d'utilisateur)
                .setIssuedAt(new Date()) // Définit la date d'émission du token
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Définit la date d'expiration du token
                .signWith(key(), SignatureAlgorithm.HS256) // Signature du token avec la clé secrète et l'algorithme HS256
                .compact(); // Construit le token compact
    }

    /**
     * Génère une clé secrète à partir de la chaîne de caractères jwtSecret encodée en Base64.
     *
     * @return La clé secrète utilisée pour signer les tokens JWT.
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)); // Décode la clé secrète en Base64 et la convertit en objet Key
    }

    /**
     * Extrait le nom d'utilisateur à partir du token JWT.
     *
     * @param token Le token JWT à partir duquel extraire le nom d'utilisateur.
     * @return Le nom d'utilisateur extrait du token JWT.
     */
    public String getUserNameFromJwtToken(String token) {
        // Parse le token et retourne le sujet du token (nom d'utilisateur)
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Valide le token JWT en vérifiant sa signature et sa validité.
     *
     * @param authToken Le token JWT à valider.
     * @return True si le token est valide, sinon False.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            // Parse le token avec la clé secrète pour vérifier sa validité
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true; // Retourne true si le token est valide
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage()); // Erreur pour un token malformé
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage()); // Erreur pour un token expiré
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage()); // Erreur pour un token non supporté
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage()); // Erreur pour une chaîne de revendications JWT vide
        }

        return false; // Retourne false si une erreur de validation est détectée
    }
}
