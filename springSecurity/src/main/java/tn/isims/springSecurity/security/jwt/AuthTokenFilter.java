package tn.isims.springSecurity.security.jwt;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tn.isims.springSecurity.security.services.UserDetailsServiceImpl;


/**
 * Filtre de sécurité qui extrait et valide le token JWT des requêtes HTTP.
 * Ce filtre vérifie la présence d'un token JWT dans les en-têtes de la requête
 * et configure l'authentification de l'utilisateur dans le contexte de sécurité de Spring.
 */
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils; // Utilitaire pour les opérations liées aux JWT, injecté depuis les composants Spring

    @Autowired
    private UserDetailsServiceImpl userDetailsService; // Service pour charger les détails de l'utilisateur, injecté depuis les composants Spring

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class); // Logger pour enregistrer les erreurs liées au filtrage des tokens

    /**
     * Exécute le filtre pour chaque requête HTTP.
     * Cette méthode extrait le token JWT, le valide, et configure l'authentification de l'utilisateur si le token est valide.
     *
     * @param request La requête HTTP à filtrer.
     * @param response La réponse HTTP associée.
     * @param filterChain La chaîne de filtres pour la requête HTTP.
     * @throws ServletException Si une erreur de servlet se produit.
     * @throws IOException Si une erreur d'entrée/sortie se produit.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request); // Extrait le token JWT depuis les en-têtes de la requête
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) { // Vérifie si le token est valide
                String username = jwtUtils.getUserNameFromJwtToken(jwt); // Extrait le nom d'utilisateur du token JWT

                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Charge les détails de l'utilisateur à partir du nom d'utilisateur
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()); // Crée un objet d'authentification avec les détails de l'utilisateur
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Ajoute les détails de la requête à l'objet d'authentification

                SecurityContextHolder.getContext().setAuthentication(authentication); // Définit l'authentification dans le contexte de sécurité
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e); // Enregistre une erreur si une exception se produit lors du traitement du token
        }

        filterChain.doFilter(request, response); // Passe la requête au prochain filtre de la chaîne
    }

    /**
     * Extrait le token JWT des en-têtes de la requête HTTP.
     *
     * @param request La requête HTTP contenant les en-têtes.
     * @return Le token JWT extrait, ou null si aucun token n'est trouvé.
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization"); // Récupère l'en-tête Authorization de la requête

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) { // Vérifie si l'en-tête contient un token JWT
            return headerAuth.substring(7); // Retourne le token JWT sans le préfixe "Bearer "
        }

        return null; // Retourne null si aucun token JWT n'est trouvé
    }
}