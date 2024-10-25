package tn.isims.springSecurity.security.jwt;


import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Point d'entrée de l'authentification JWT.
 * Cette classe est utilisée pour gérer les erreurs d'authentification non autorisée.
 * Elle est appelée lorsque l'utilisateur tente d'accéder à une ressource protégée sans être authentifié.
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class); // Logger pour enregistrer les erreurs d'authentification

    /**
     * Gère les erreurs d'authentification en envoyant une réponse HTTP 401 (Non autorisé) au client.
     * Cette méthode est appelée lorsque l'utilisateur tente d'accéder à une ressource protégée sans être authentifié.
     *
     * @param request La requête HTTP qui a échoué à l'authentification.
     * @param response La réponse HTTP à envoyer au client.
     * @param authException L'exception d'authentification qui a été levée.
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de l'écriture de la réponse.
     * @throws ServletException Si une erreur de servlet se produit.
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage()); // Enregistre l'erreur d'authentification dans les logs

        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // Définit le type de contenu de la réponse en JSON
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // Définit le code de statut HTTP à 401 (Non autorisé)

        final Map<String, Object> body = new HashMap<>(); // Crée un corps de réponse sous forme de Map
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED); // Ajoute le code de statut à la réponse
        body.put("error", "Unauthorized"); // Ajoute un message d'erreur à la réponse
        body.put("message", authException.getMessage()); // Ajoute le message de l'exception d'authentification
        body.put("path", request.getServletPath()); // Ajoute le chemin de la requête à la réponse

        final ObjectMapper mapper = new ObjectMapper(); // Crée un objet ObjectMapper pour convertir le corps de la réponse en JSON
        mapper.writeValue(response.getOutputStream(), body); // Écrit le corps de la réponse JSON dans le flux de sortie de la réponse HTTP
    }

}