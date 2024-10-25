package tn.isims.springSecurity.payload.response;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data @AllArgsConstructor @NoArgsConstructor
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;

    private String email;
    private List<String> roles;


    public JwtResponse(String accessToken, Long id, String email, List<String> roles) {
        this.token = accessToken;
        this.id = id;

        this.email = email;
        this.roles = roles;
    }

}