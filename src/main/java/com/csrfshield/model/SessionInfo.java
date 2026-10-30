package com.csrfshield.model;

import java.time.Instant;

/**
 * Everything the server tracks about one logged-in session, used purely for
 * CSRF defense: the current token, when it expires, and the client
 * fingerprint (IP + User-Agent) it is bound to.
 */
public class SessionInfo {
    private final String sessionId;
    private final String username;
    private String csrfToken;
    private Instant tokenIssuedAt;
    private Instant tokenExpiresAt;
    private final String boundIp;
    private final String boundUserAgent;

    public SessionInfo(String sessionId, String username, String boundIp, String boundUserAgent) {
        this.sessionId = sessionId;
        this.username = username;
        this.boundIp = boundIp;
        this.boundUserAgent = boundUserAgent;
    }

    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public String getCsrfToken() { return csrfToken; }
    public String getBoundIp() { return boundIp; }
    public String getBoundUserAgent() { return boundUserAgent; }
    public Instant getTokenExpiresAt() { return tokenExpiresAt; }

    public void rotateToken(String newToken, Instant issuedAt, Instant expiresAt) {
        this.csrfToken = newToken;
        this.tokenIssuedAt = issuedAt;
        this.tokenExpiresAt = expiresAt;
    }

    public boolean isTokenExpired() {
        return tokenExpiresAt == null || Instant.now().isAfter(tokenExpiresAt);
    }
}
