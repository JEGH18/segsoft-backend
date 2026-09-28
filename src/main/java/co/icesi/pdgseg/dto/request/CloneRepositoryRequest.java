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

    // Optional: only needed for private repositories. Personal Access Token
    // (GitHub/GitLab/Bitbucket all support this over HTTPS). Never persisted,
    // never logged -- used once to build the URL passed to `git clone`, then
    // discarded. gitUrl itself must stay credential-free; embedding a token
    // there instead is rejected (see GitCloneService).
    @Size(max = 500, message = "Token demasiado largo")
    private String accessToken;

    public String getGitUrl() { return gitUrl; }
    public void setGitUrl(String gitUrl) { this.gitUrl = gitUrl; }

    public String getBranch() { return branch != null && !branch.isBlank() ? branch : "main"; }
    public void setBranch(String branch) { this.branch = branch; }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
}
