package com.csrfshield.model;

import java.time.Instant;
import java.util.UUID;

/**
 * One row in the Security Dashboard - either a VALID (green) request or a
 * SUSPICIOUS (red) one, with enough detail to explain the verdict.
 */
public class RequestLog {

    public enum Verdict { VALID, SUSPICIOUS }

    private final String requestId;
    private final Instant timestamp;
    private final String username;
    private final String action;          // e.g. "PASSWORD_CHANGE", "MONEY_TRANSFER"
    private final String ip;
    private final String origin;
    private final String tokenStatus;     // e.g. "VALID", "MISSING", "EXPIRED", "MISMATCH"
    private final Verdict verdict;
    private final String reason;          // why it was flagged, or "OK"
    private final String mode;            // ATTACK or DEFENSE, whichever was active

    public RequestLog(String username, String action, String ip, String origin,
                       String tokenStatus, Verdict verdict, String reason, String mode) {
        this.requestId = UUID.randomUUID().toString().substring(0, 8);
        this.timestamp = Instant.now();
        this.username = username;
        this.action = action;
        this.ip = ip;
        this.origin = origin;
        this.tokenStatus = tokenStatus;
        this.verdict = verdict;
        this.reason = reason;
        this.mode = mode;
    }

    public String getRequestId() { return requestId; }
    public Instant getTimestamp() { return timestamp; }
    public String getUsername() { return username; }
    public String getAction() { return action; }
    public String getIp() { return ip; }
    public String getOrigin() { return origin; }
    public String getTokenStatus() { return tokenStatus; }
    public Verdict getVerdict() { return verdict; }
    public String getReason() { return reason; }
    public String getMode() { return mode; }
}
