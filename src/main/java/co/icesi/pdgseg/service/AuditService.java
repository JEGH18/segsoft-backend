package co.icesi.pdgseg.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public AuditService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void record(String eventType, String username, String ipAddress, Map<String, Object> details) {
        try {
            String detailsJson = objectMapper.writeValueAsString(details);
            jdbcTemplate.update(
                    "INSERT INTO auth_audit_log (event_type, username, ip_address, details) " +
                            "VALUES (?, ?, ?, ?::jsonb)",
                    eventType, username, ipAddress, detailsJson
            );
        } catch (Exception e) {
            log.error("Failed to record audit event={} user={}", eventType, username, e);
        }
    }
}
