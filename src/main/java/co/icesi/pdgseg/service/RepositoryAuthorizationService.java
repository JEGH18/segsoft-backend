package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class RepositoryAuthorizationService {

    private final RepositoryRepository repositoryRepository;

    public RepositoryAuthorizationService(RepositoryRepository repositoryRepository) {
        this.repositoryRepository = repositoryRepository;
    }

    public boolean canModify(UUID repoId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasAuthority(authentication, "ROLE_SECURITY_ADMIN")) {
            return true;
        }
        Optional<Repository> repository = repositoryRepository.findById(repoId);
        if (repository.isEmpty()) {
            return true;
        }
        return repository.get().getUser().getUsername().equals(authentication.getName());
    }

    public boolean canRead(UUID repoId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasAuthority(authentication, "ROLE_SECURITY_ADMIN") || hasAuthority(authentication, "ROLE_AUDITOR")) {
            return true;
        }
        Optional<Repository> repository = repositoryRepository.findById(repoId);
        if (repository.isEmpty()) {
            return true;
        }
        return repository.get().getUser().getUsername().equals(authentication.getName());
    }

    private boolean hasAuthority(Authentication authentication, String authority) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority::equals);
    }
}
