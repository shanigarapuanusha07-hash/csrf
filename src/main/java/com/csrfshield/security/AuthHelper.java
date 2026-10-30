package com.csrfshield.security;

import com.csrfshield.model.SessionInfo;
import com.csrfshield.store.SessionStore;
import com.csrfshield.util.RequestUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class AuthHelper {

    private final SessionStore sessionStore;

    public AuthHelper(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    public SessionInfo currentSession(HttpServletRequest request) {
        String sessionId = RequestUtil.cookieValue(request, CookieUtil.SESSION_COOKIE);
        return sessionStore.get(sessionId);
    }

    public boolean isAuthenticated(HttpServletRequest request) {
        return currentSession(request) != null;
    }
}
