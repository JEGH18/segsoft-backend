package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.FindingRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service("analysisAuthorizationService")
public class AnalysisAuthorizationService {

    private final RepositoryRepository repositoryRepository;
    private final AnalysisRepository analysisRepository;
    private final FindingRepository findingRepository;

    public AnalysisAuthorizationService(
            RepositoryRepository repositoryRepository,
            AnalysisRepository analysisRepository,
            FindingRepository findingRepository
    ) {
        this.repositoryRepository = repositoryRepository;
        this.analysisRepository = analysisRepository;
        this.findingRepository = findingRepository;
    }

    public boolean canAccessRepository(UUID repositoryId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasAuditorRole(authentication)) {
            return true;
        }
        Repository repository = repositoryRepository.findById(repositoryId).orElse(null);
        return repository != null && repository.getUser().getUsername().equals(authentication.getName());
    }

    public boolean canAccessAnalysis(UUID analysisId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasAuditorRole(authentication)) {
            return true;
        }
        Analysis analysis = analysisRepository.findById(analysisId).orElse(null);
        return analysis != null && analysis.getRepository().getUser().getUsername().equals(authentication.getName());
    }

    public boolean canAccessFinding(UUID findingId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasAuditorRole(authentication)) {
            return true;
        }
        return findingRepository.findById(findingId)
                .map(finding -> finding.getAnalysis().getRepository().getUser().getUsername().equals(authentication.getName()))
                .orElse(false);
    }

    private boolean hasAuditorRole(Authentication authentication) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String role = authority.getAuthority();
            if ("ROLE_AUDITOR".equals(role) || "ROLE_SECURITY_ADMIN".equals(role)) {
                return true;
            }
        }
        return false;
    }
}
