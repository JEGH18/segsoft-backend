package co.icesi.pdgseg.dto.response;

import java.util.List;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        List<String> roles
) {
    public AuthResponse(String accessToken, String refreshToken, List<String> roles) {
        this(accessToken, refreshToken, "Bearer", roles);
    }
}
