package db.migration;

import co.icesi.pdgseg.service.ReportChecksum;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HexFormat;

/**
 * Moves reports.content_json (TEXT) to reports.content (JSONB).
 *
 * JSONB does not keep the original bytes, so a checksum over the stored
 * text can no longer be recomputed; reports switch to {@link ReportChecksum}
 * (SHA-256 of the canonical JSON). Only rows whose old checksum still
 * verifies against their text are re-sealed with the new one: a row that was
 * already tampered with keeps its old checksum and keeps failing
 * verification, so the migration never launders a manipulation.
 */
public class V32__reports_content_jsonb extends BaseJavaMigration {

    @Override
    public void migrate(Context context) throws Exception {
        Connection connection = context.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE reports ADD COLUMN content JSONB");
            statement.execute("UPDATE reports SET content = content_json::jsonb");
        }

        try (PreparedStatement select = connection.prepareStatement("SELECT id, content_json, checksum FROM reports");
             PreparedStatement reseal = connection.prepareStatement("UPDATE reports SET checksum = ? WHERE id = ?");
             ResultSet rows = select.executeQuery()) {
            while (rows.next()) {
                String text = rows.getString("content_json");
                String storedChecksum = rows.getString("checksum");
                if (textSha256(text).equalsIgnoreCase(storedChecksum)) {
                    reseal.setString(1, ReportChecksum.of(text));
                    reseal.setObject(2, rows.getObject("id"));
                    reseal.addBatch();
                }
            }
            reseal.executeBatch();
        }

        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE reports DROP COLUMN content_json");
            statement.execute("ALTER TABLE reports ALTER COLUMN content SET NOT NULL");
        }
    }

    /** The V31 checksum: SHA-256 of the exact stored text. */
    private static String textSha256(String text) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
