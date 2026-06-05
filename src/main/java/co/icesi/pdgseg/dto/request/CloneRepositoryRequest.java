package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class CloneRepositoryRequest {

    @NotBlank(message = "La URL Git es obligatoria")
    @Pattern(regexp = "^https?://.*", message = "La URL debe empezar con http:// o https://")
    @Size(max = 1000, message = "URL demasiado larga")
    private String gitUrl;

    @Size(max = 200, message = "Nombre de branch demasiado largo")
    private String branch = "main";

    public String getGitUrl() { return gitUrl; }
    public void setGitUrl(String gitUrl) { this.gitUrl = gitUrl; }

    public String getBranch() { return branch != null && !branch.isBlank() ? branch : "main"; }
    public void setBranch(String branch) { this.branch = branch; }
}
