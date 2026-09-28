package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.response.Iso27002ControlResponse;
import co.icesi.pdgseg.dto.response.NistControlResponse;
import co.icesi.pdgseg.entity.enums.Iso27002Category;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.AuditService;
import co.icesi.pdgseg.service.FrameworkControlService;
import co.icesi.pdgseg.service.Iso27002ControlService;
import co.icesi.pdgseg.service.NistControlService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Escenario 2 de "Incorporar políticas basadas en NIST al catálogo":
 * GET /api/v1/frameworks/nist/controls. @WebMvcTest slice needs AuditService
 * @MockBean'd (GlobalExceptionHandler requires it), same workaround already
 * used in PolicySetControllerTest.
 */
@WebMvcTest(FrameworkController.class)
@Import(SecurityConfig.class)
class FrameworkControllerTest {

    @Autowired MockMvc mockMvc;

    @MockBean FrameworkControlService frameworkControlService;
    @MockBean NistControlService nistControlService;
    @MockBean Iso27002ControlService iso27002ControlService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;
    @MockBean AuditService auditService;

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void iso27002Controls_groupedByThematicCategory_returnsAllFields() throws Exception {
        when(iso27002ControlService.getControls(isNull(), isNull())).thenReturn(List.of(
            new Iso27002ControlResponse("5.1", "Policies for information security", "ORGANIZATIONAL", "Guía 5.1"),
            new Iso27002ControlResponse("6.1", "Screening", "PEOPLE", "Guía 6.1"),
            new Iso27002ControlResponse("7.1", "Physical security perimeters", "PHYSICAL", "Guía 7.1"),
            new Iso27002ControlResponse("8.24", "Use of cryptography", "TECHNOLOGICAL", "Guía 8.24")
        ));

        mockMvc.perform(get("/api/v1/frameworks/iso-27002/controls"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(4))
            .andExpect(jsonPath("$[0].category").value("ORGANIZATIONAL"))
            .andExpect(jsonPath("$[1].category").value("PEOPLE"))
            .andExpect(jsonPath("$[2].category").value("PHYSICAL"))
            .andExpect(jsonPath("$[3].id").value("8.24"))
            .andExpect(jsonPath("$[3].title").value("Use of cryptography"))
            .andExpect(jsonPath("$[3].category").value("TECHNOLOGICAL"))
            .andExpect(jsonPath("$[3].implementationGuidance").value("Guía 8.24"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void iso27002Controls_filteredByRelatedControl() throws Exception {
        when(iso27002ControlService.getControls(isNull(), org.mockito.ArgumentMatchers.eq("A.8.24")))
            .thenReturn(List.of(new Iso27002ControlResponse("8.24", "Use of cryptography", "TECHNOLOGICAL", "Guía 8.24")));

        mockMvc.perform(get("/api/v1/frameworks/iso-27002/controls").param("relatedControl", "A.8.24"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].id").value("8.24"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void iso27002Controls_filteredByCategory() throws Exception {
        when(iso27002ControlService.getControls(Iso27002Category.TECHNOLOGICAL, null))
            .thenReturn(List.of(new Iso27002ControlResponse("8.5", "Secure authentication", "TECHNOLOGICAL", "Guía 8.5")));

        mockMvc.perform(get("/api/v1/frameworks/iso-27002/controls").param("category", "TECHNOLOGICAL"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].category").value("TECHNOLOGICAL"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void nistControls_groupedByFamily_returnsIdTitleFamily() throws Exception {
        when(nistControlService.getControls(isNull())).thenReturn(List.of(
            new NistControlResponse("AC-2", "Account Management", "AC"),
            new NistControlResponse("AU-2", "Event Logging", "AU"),
            new NistControlResponse("SC-13", "Cryptographic Protection", "SC"),
            new NistControlResponse("SI-10", "Information Input Validation", "SI")
        ));

        mockMvc.perform(get("/api/v1/frameworks/nist/controls"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(4))
            .andExpect(jsonPath("$[0].id").value("AC-2"))
            .andExpect(jsonPath("$[0].title").value("Account Management"))
            .andExpect(jsonPath("$[0].family").value("AC"))
            .andExpect(jsonPath("$[2].id").value("SC-13"))
            .andExpect(jsonPath("$[2].family").value("SC"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void nistControls_filteredByFamily_anyAuthenticatedRole() throws Exception {
        when(nistControlService.getControls("SC")).thenReturn(List.of(
            new NistControlResponse("SC-8", "Transmission Confidentiality and Integrity", "SC"),
            new NistControlResponse("SC-13", "Cryptographic Protection", "SC")
        ));

        mockMvc.perform(get("/api/v1/frameworks/nist/controls").param("family", "SC"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[*].family", org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("SC"))));
    }

    @Test
    void nistControls_withoutAuth_returns401or403() throws Exception {
        mockMvc.perform(get("/api/v1/frameworks/nist/controls"))
            .andExpect(result -> {
                int status = result.getResponse().getStatus();
                org.assertj.core.api.Assertions.assertThat(status).isIn(401, 403);
            });
    }
}
