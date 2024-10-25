package tn.isims.springSecurity.security.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tn.isims.springSecurity.entity.User;
import tn.isims.springSecurity.repository.UserRepository;


/**
 * Implémentation de l'interface UserDetailsService de Spring Security.
 * Cette classe fournit les détails utilisateur à Spring Security pour l'authentification.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository; // Dépendance injectée pour accéder aux données utilisateur

    /**
     * Charge un utilisateur en fonction de son nom d'utilisateur.
     * Cette méthode est utilisée par Spring Security pour obtenir les détails de l'utilisateur lors de l'authentification.
     *
     * @param email Le email de l'utilisateur à charger.
     * @return Un objet UserDetails contenant les détails de l'utilisateur.
     * @throws EmaileNotFoundException Si aucun utilisateur n'est trouvé avec le nom d'utilisateur fourni.
     */




    /**Utilisation : Lorsqu'un utilisateur tente de s'authentifier, Spring Security
     *  appelle la méthode loadUserByUsername() de UserDetailsServiceImpl pour récupérer
     *  les détails de l'utilisateur. La méthode recherche l'utilisateur par nom d'utilisateur, puis renvoie une instance de UserDetailsImpl
     *  qui contient toutes les informations nécessaires pour l'authentification.**/
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Cherche l'utilisateur dans la base de données en utilisant le nom d'utilisateur
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));

        // Convertit l'entité User en UserDetailsImpl et le retourne
        return UserDetailsImpl.build(user);
    }
}