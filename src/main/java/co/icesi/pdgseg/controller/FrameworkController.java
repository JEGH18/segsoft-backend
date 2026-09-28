package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.response.FrameworkControlResponse;
import co.icesi.pdgseg.dto.response.Iso27002ControlResponse;
import co.icesi.pdgseg.dto.response.NistControlResponse;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.Iso27002Category;
import co.icesi.pdgseg.service.FrameworkControlService;
import co.icesi.pdgseg.service.Iso27002ControlService;
import co.icesi.pdgseg.service.NistControlService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/frameworks")
@Tag(name = "Marcos normativos", description = "Catálogo de controles por marco normativo")
@SecurityRequirement(name = "bearerAuth")
public class FrameworkController {

    private final FrameworkControlService frameworkControlService;
    private final NistControlService nistControlService;
    private final Iso27002ControlService iso27002ControlService;

    public FrameworkController(FrameworkControlService frameworkControlService,
                                NistControlService nistControlService,
                                Iso27002ControlService iso27002ControlService) {
        this.frameworkControlService = frameworkControlService;
        this.nistControlService = nistControlService;
        this.iso27002ControlService = iso27002ControlService;
    }

    // Both declared before the generic "/{framework}/controls" below: Spring
    // MVC ranks a literal path segment as more specific than a path
    // variable at the same position, so requests for exactly these two
    // literal paths resolve here rather than attempting (and failing) to
    // parse "nist"/"iso-27002" as a Framework enum value.
    @GetMapping("/iso-27002/controls")
    @Operation(
        summary = "Catálogo de controles ISO/IEC 27002",
        description = "Catálogo de guías de implementación de ISO/IEC 27002:2022, agrupado en las 4 categorías " +
            "temáticas de la norma (Organizacionales, Personas, Físicos, Tecnológicos). Filtrable por categoría " +
            "y/o por el control de ISO/IEC 27001 Anexo A relacionado (ej. relatedControl=A.8.24)."
    )
    public List<Iso27002ControlResponse> iso27002Controls(
            @RequestParam(required = false) Iso27002Category category,
            @RequestParam(required = false) String relatedControl) {
        return iso27002ControlService.getControls(category, relatedControl);
    }

    @GetMapping("/nist/controls")
    @Operation(
        summary = "Catálogo de controles NIST SP 800-53",
        description = "Catálogo de referencia de controles NIST agrupados por familia (AC, AU, IA, SC, SI...), " +
            "filtrable por familia. Distinto del catálogo derivador de control_id por categoría " +
            "(ver /{framework}/controls): este es el catálogo amplio para explorar/elegir un control real."
    )
    public List<NistControlResponse> nistControls(@RequestParam(required = false) String family) {
        return nistControlService.getControls(family);
    }

    @GetMapping("/{framework}/controls")
    @Operation(
        summary = "Controles disponibles para un marco normativo",
        description = "Para cada categoría CCS soportada por el marco, retorna el control_id y " +
            "nombre oficiales, de modo que el cliente pueda derivar el control automáticamente " +
            "en vez de pedirlo como texto libre. CUSTOM no tiene catálogo: " +
            "responde una lista vacía porque son políticas definidas por el equipo, sin norma externa."
    )
    public List<FrameworkControlResponse> controlsFor(@PathVariable Framework framework) {
        return frameworkControlService.getControlsFor(framework);
    }
}
