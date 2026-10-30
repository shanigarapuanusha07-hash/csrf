package com.csrfshield.store;

import com.csrfshield.model.SessionInfo;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side session registry, keyed by our own opaque session-id cookie
 * value (NOT the JSESSIONID -- we manage this ourselves so we control every
 * cookie attribute explicitly).
 */
@Component
public class SessionStore {

    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();

    public void put(String sessionId, SessionInfo info) {
        sessions.put(sessionId, info);
    }

    public SessionInfo get(String sessionId) {
        return sessionId == null ? null : sessions.get(sessionId);
    }

    public void invalidate(String sessionId) {
        sessions.remove(sessionId);
    }
}
