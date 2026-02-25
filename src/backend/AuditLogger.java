package backend;

/**
 *
 * @author marcusuy
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class AuditLogger {
    private static final String LOG_FILE = "bank_audit.log";
    private static final String SECRET_KEY = "SuperSecretAuditKey123"; 

    public static void logTransaction(String clientID, String action, double amount, String status) {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String logEntry = timestamp + " | User: " + clientID + " | Action: " + action +
                              (amount >= 0 ? " | Amount: $" + amount : "") + " | Status: " + status;
            
            // Encrypt log entry
            String encryptedLog = encryptLog(logEntry);

            // Append to log file
            Files.write(Paths.get(LOG_FILE), (encryptedLog + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encryptLog(String logEntry) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = digest.digest((logEntry + SECRET_KEY).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashedBytes) + " | " + logEntry; // Store hash + log
    }
}
