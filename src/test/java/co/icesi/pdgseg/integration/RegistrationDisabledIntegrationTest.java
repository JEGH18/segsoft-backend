package co.icesi.pdgseg.integration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** With SEGSOFT_REGISTRATION_ENABLED=false the public API creates no accounts. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "cors.allowed-origins=http://localhost:5173",
                "auth.registration.enabled=false"
        }
)
@AutoConfigureMockMvc
class RegistrationDisabledIntegrationTest extends PostgreSQLContainerBase {

    @Autowired private MockMvc mockMvc;

    @Test
    void register_isForbiddenAndTheStatusSaysSo() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"nadie\",\"password\":\"Registro-Prueba-2026!\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("REGISTRATION_DISABLED"));

        mockMvc.perform(get("/api/v1/auth/registration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
    }
}
