package co.icesi.pdgseg.service;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class SecretMaskingService {

    private static final String MASK = "*****";
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("(?i)(api[_-]?key\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)"),
            Pattern.compile("(?i)(secret\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)"),
            Pattern.compile("(?i)(token\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)"),
            Pattern.compile("(?i)(password\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)"),
            Pattern.compile("(?i)(passwd\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)"),
            Pattern.compile("(?i)(pwd\\s*[:=]\\s*[\"']?)([^\\s\"']+)([\"']?)")
    );

    public String mask(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String masked = value;
        for (Pattern pattern : SECRET_PATTERNS) {
            masked = pattern.matcher(masked).replaceAll("$1" + MASK + "$3");
        }
        return masked;
    }
}
