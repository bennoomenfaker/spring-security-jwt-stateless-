package tn.isims.springSecurity.controller;

import java.util.*;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import tn.isims.springSecurity.entity.ERole;
import tn.isims.springSecurity.entity.Role;
import tn.isims.springSecurity.entity.User;
import tn.isims.springSecurity.payload.request.LoginRequest;
import tn.isims.springSecurity.payload.request.SignupRequest;
import tn.isims.springSecurity.payload.response.JwtResponse;
import tn.isims.springSecurity.payload.response.MessageResponse;
import tn.isims.springSecurity.repository.RoleRepository;
import tn.isims.springSecurity.repository.UserRepository;
import tn.isims.springSecurity.security.jwt.JwtUtils;
import tn.isims.springSecurity.security.services.UserDetailsImpl;


@CrossOrigin(origins = "*", maxAge = 3600) // Permet les requêtes provenant de n'importe quelle origine et définit la durée de vie du cache CORS
@RestController // Indique que cette classe est un contrôleur REST
@RequestMapping("/api/auth") // Définit la base de l'URL pour toutes les méthodes de ce contrôleur
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager; // Injecte le gestionnaire d'authentification

    @Autowired
    UserRepository userRepository; // Injecte le dépôt des utilisateurs

    @Autowired
    RoleRepository roleRepository; // Injecte le dépôt des rôles

    @Autowired
    PasswordEncoder encoder; // Injecte l'encodeur de mots de passe

    @Autowired
    JwtUtils jwtUtils; // Injecte les utilitaires JWT pour la génération et la validation des tokens

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // Authentifie l'utilisateur en utilisant les informations de connexion fournies
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        // Stocke l'authentification dans le contexte de sécurité
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Génère un token JWT pour l'utilisateur authentifié
        String jwt = jwtUtils.generateJwtToken(authentication);

        // Récupère les détails de l'utilisateur et les rôles
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Retourne une réponse contenant le token JWT, les informations de l'utilisateur et ses rôles
        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getEmail(),
                roles));
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

        // Vérifie si l'email est déjà utilisé
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Si la méthode d'inscription n'est pas fournie, on utilise "app" par défaut
        String signupMethod = (signUpRequest.getSignupMethod() != null) ? signUpRequest.getSignupMethod() : "app";

        // Crée un nouveau compte utilisateur avec la méthode d'inscription
        User user = new User(signUpRequest.getFirstname(),  // Utilisation du prénom
                signUpRequest.getLastname(),  // Utilisation du nom de famille
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signupMethod); // Ajout du signupMethod

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        // Assigne les rôles à l'utilisateur
        if (strRoles == null) {
            // Si aucun rôle n'est spécifié, attribue le rôle utilisateur par défaut
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            // Assigne les rôles en fonction de la demande
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        // Assigne les rôles au nouvel utilisateur et enregistre dans la base de données
        user.setRoles(roles);
        userRepository.save(user);

        // Retourne une réponse indiquant que l'utilisateur a été enregistré avec succès
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Boolean>> validateToken(@RequestParam("token") String token) {
        boolean isValid = jwtUtils.validateJwtToken(token);

        Map<String, Boolean> response = new HashMap<>();
        response.put("isValid", isValid);

        return ResponseEntity.ok(response);
    }


    @GetMapping("/role")
    public Collection<String> getUserRoles(@RequestHeader("Authorization") String authHeader) {
        // Extraire le token de l'en-tête Authorization
        String token = authHeader.replace("Bearer ", "");

        // Pour simplifier, supposons que la vérification du token est effectuée ici.
        // En pratique, vous auriez une méthode pour valider et extraire les rôles du token JWT.

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new RuntimeException("User not authenticated");
        }

        // Obtenir les rôles de l'utilisateur
        return authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.toList());
    }
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getUserDetails(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");

        // Créer la map de réponse
        Map<String, Object> response = new HashMap<>();

        // Vérifier si le token est valide
        boolean isValid = jwtUtils.validateJwtToken(token);
        response.put("isValid", isValid);

        if (isValid) {
            // Récupérer le nom d'utilisateur depuis le token
            String username = jwtUtils.getUserNameFromJwtToken(token);

            // Trouver l'utilisateur dans la base de données par email
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("Error: User not found."));

            // Ajouter les détails de l'utilisateur à la réponse
            response.put("user", user);
        }

        // Retourner la réponse avec isValid et les détails de l'utilisateur (si valide)
        return ResponseEntity.ok(response);
    }


    @GetMapping("/findByEmail/{email}")
    public ResponseEntity<Boolean> findByEmail(@PathVariable String email) {
        Boolean exists = userRepository.existsByEmail(email);
        return ResponseEntity.ok(exists);
    }





}