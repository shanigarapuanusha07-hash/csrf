package com.csrfshield.security;

import com.csrfshield.model.SessionInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Generates and validates per-session CSRF tokens.
 *
 * Design (synchronizer-token pattern, HMAC-signed so the token is
 * self-verifying and can also be checked stateless-side if ever needed):
 *
 *   token = base64( random(32 bytes) ) + "." + expiryEpochSeconds
 *   signature = HMAC-SHA256(serverSecret, sessionId + "|" + token)
 *   final token sent to client = token + "." + hex(signature)
 *
 * Validation re-derives the signature and rejects on any mismatch, then
 * separately checks expiry and IP/User-Agent binding recorded server-side
 * in the SessionInfo.
 */
@Component
public class CsrfTokenManager {

    private final byte[] serverSecret;
    private final SecureRandom random = new SecureRandom();

    @Value("${csrf.token.expiry.seconds:300}")
    private long tokenExpirySeconds;

    public CsrfTokenManager() {
        this.serverSecret = new byte[32];
        random.nextBytes(serverSecret);
    }

    public long getExpirySeconds() { return tokenExpirySeconds; }

    /** Generates a brand-new token, records it (with expiry) on the session, and returns it. */
    public String issueToken(SessionInfo session) {
        byte[] rand = new byte[32];
        random.nextBytes(rand);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(rand);

        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(tokenExpirySeconds);
        String payload = randomPart + "." + expiry.getEpochSecond();

        String signature = sign(session.getSessionId() + "|" + payload);
        String fullToken = payload + "." + signature;

        session.rotateToken(fullToken, now, expiry);
        return fullToken;
    }

    public enum ValidationResult {
        VALID, MISSING, MALFORMED, BAD_SIGNATURE, EXPIRED, SESSION_MISMATCH, IP_MISMATCH, UA_MISMATCH
    }

    /**
     * Validates a token presented by the client against what the server
     * expects for this session, including IP / User-Agent binding.
     */
    public ValidationResult validate(SessionInfo session, String presentedToken,
                                      String requestIp, String requestUserAgent,
                                      boolean bindIp, boolean bindUserAgent) {
        if (presentedToken == null || presentedToken.isBlank()) {
            return ValidationResult.MISSING;
        }
        String[] parts = presentedToken.split("\\.");
        if (parts.length != 3) {
            return ValidationResult.MALFORMED;
        }
        String randomPart = parts[0];
        String expiryPart = parts[1];
        String signaturePart = parts[2];

        String payload = randomPart + "." + expiryPart;
        String expectedSignature = sign(session.getSessionId() + "|" + payload);
        if (!constantTimeEquals(expectedSignature, signaturePart)) {
            return ValidationResult.BAD_SIGNATURE;
        }

        // Must also match the exact live token on the session (single active token / rotation)
        if (session.getCsrfToken() == null || !session.getCsrfToken().equals(presentedToken)) {
            return ValidationResult.SESSION_MISMATCH;
        }

        if (session.isTokenExpired()) {
            return ValidationResult.EXPIRED;
        }

        if (bindIp && session.getBoundIp() != null && !session.getBoundIp().equals(requestIp)) {
            return ValidationResult.IP_MISMATCH;
        }

        if (bindUserAgent && session.getBoundUserAgent() != null
                && !session.getBoundUserAgent().equals(requestUserAgent)) {
            return ValidationResult.UA_MISMATCH;
        }

        return ValidationResult.VALID;
    }

    private String sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(serverSecret, "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC signing failed", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
