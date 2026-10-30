package com.csrfshield.security;

import com.csrfshield.model.RequestLog;
import com.csrfshield.model.SessionInfo;
import com.csrfshield.store.LogStore;
import com.csrfshield.store.SessionStore;
import com.csrfshield.util.RequestUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * Guards every "sensitive" state-changing endpoint (password change,
 * profile update, money transfer). Runs a layered set of checks and, in
 * DEFENSE mode, rejects the request the moment any layer fails. In ATTACK
 * mode the checks are intentionally bypassed so the malicious-site demo can
 * show what CSRF looks like when none of this exists.
 *
 * Layers, in order:
 *   1. Session must exist (user must be authenticated)
 *   2. Origin / Referer header must match this application's own origin
 *   3. AJAX/JSON requests must carry the custom header we require
 *   4. CSRF token must be present, correctly signed, unexpired, and bound
 *      to the same session, IP and User-Agent that received it
 */
@Component
public class CsrfFilter extends OncePerRequestFilter {

    private static final Set<String> PROTECTED_PATHS = Set.of(
            "/profile/update", "/password/change", "/transfer",
            "/api/profile/update", "/api/password/change", "/api/transfer"
    );
    private static final Set<String> JSON_PATHS = Set.of(
            "/api/profile/update", "/api/password/change", "/api/transfer"
    );

    private final SessionStore sessionStore;
    private final CsrfTokenManager tokenManager;
    private final LogStore logStore;
    private final AppMode appMode;

    @Value("${csrf.bind.ip:true}")
    private boolean bindIp;
    @Value("${csrf.bind.useragent:true}")
    private boolean bindUserAgent;

    /** The only Origins/Referers we ever trust for state-changing requests. */
    private final List<String> trustedOrigins = List.of(
            "http://localhost:8080", "https://localhost:8080"
    );

    public CsrfFilter(SessionStore sessionStore, CsrfTokenManager tokenManager,
                       LogStore logStore, AppMode appMode) {
        this.sessionStore = sessionStore;
        this.tokenManager = tokenManager;
        this.logStore = logStore;
        this.appMode = appMode;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod())
                || !PROTECTED_PATHS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String ip = RequestUtil.clientIp(request);
        String userAgent = safe(request.getHeader("User-Agent"));
        String origin = firstNonBlank(request.getHeader("Origin"), refererOrigin(request));
        String action = actionNameFor(path);

        String sessionId = RequestUtil.cookieValue(request, CookieUtil.SESSION_COOKIE);
        SessionInfo session = sessionStore.get(sessionId);

        if (session == null) {
            reject(response, 401, "No session cookie");
            log(null, action, ip, origin, "NO_SESSION", RequestLog.Verdict.SUSPICIOUS,
                    "Request to a protected endpoint with no valid session");
            return;
        }

        String username = session.getUsername();

        // ---- ATTACK MODE: deliberately skip every defense to show the raw vulnerability ----
        if (appMode.get() == AppMode.Mode.ATTACK) {
            log(username, action, ip, origin, "BYPASSED", RequestLog.Verdict.SUSPICIOUS,
                    "Attack Mode active - CSRF checks were bypassed and the request was allowed through");
            chain.doFilter(request, response);
            return;
        }

        // ---- DEFENSE MODE ----

        // 1. Origin / Referer validation
        if (origin == null || !trustedOrigins.contains(origin)) {
            reject(response, 403, "Origin/Referer check failed");
            log(username, action, ip, origin, "N/A", RequestLog.Verdict.SUSPICIOUS,
                    "Origin/Referer mismatch (got '" + origin + "') - likely cross-site request");
            return;
        }

        // 2. Custom header requirement for AJAX/JSON endpoints
        if (JSON_PATHS.contains(path)) {
            String requestedWith = request.getHeader("X-Requested-With");
            String csrfHeader = request.getHeader("X-CSRF-Token");
            if (!"XMLHttpRequest".equals(requestedWith) || csrfHeader == null) {
                reject(response, 403, "Missing required AJAX headers");
                log(username, action, ip, origin, "N/A", RequestLog.Verdict.SUSPICIOUS,
                        "JSON endpoint missing X-Requested-With / X-CSRF-Token custom header "
                                + "(cross-site forms cannot set custom headers)");
                return;
            }
        }

        // 3. Token extraction: header for JSON endpoints, form field otherwise
        String presentedToken = JSON_PATHS.contains(path)
                ? request.getHeader("X-CSRF-Token")
                : request.getParameter("_csrf");

        CsrfTokenManager.ValidationResult result = tokenManager.validate(
                session, presentedToken, ip, userAgent, bindIp, bindUserAgent);

        if (result != CsrfTokenManager.ValidationResult.VALID) {
            reject(response, 403, "CSRF token validation failed: " + result);
            int failures = logStore.getFailureCount(ip, username) + 1;
            String reason = describeFailure(result) + (failures >= 3
                    ? " (" + failures + " consecutive failed attempts from this client)" : "");
            log(username, action, ip, origin, result.name(), RequestLog.Verdict.SUSPICIOUS, reason);
            return;
        }

        // All checks passed
        log(username, action, ip, origin, "VALID", RequestLog.Verdict.VALID, "OK");
        chain.doFilter(request, response);
    }

    private String describeFailure(CsrfTokenManager.ValidationResult result) {
        return switch (result) {
            case MISSING -> "No CSRF token was submitted with the request";
            case MALFORMED -> "CSRF token was malformed";
            case BAD_SIGNATURE -> "CSRF token signature invalid (forged or tampered token)";
            case SESSION_MISMATCH -> "Token does not match the token issued to this session";
            case EXPIRED -> "CSRF token has expired";
            case IP_MISMATCH -> "Token was bound to a different IP address";
            case UA_MISMATCH -> "Token was bound to a different User-Agent";
            default -> "Unknown validation failure";
        };
    }

    private String actionNameFor(String path) {
        if (path.contains("password")) return "PASSWORD_CHANGE";
        if (path.contains("profile")) return "PROFILE_UPDATE";
        if (path.contains("transfer")) return "MONEY_TRANSFER";
        return "UNKNOWN_ACTION";
    }

    private void reject(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private void log(String username, String action, String ip, String origin, String tokenStatus,
                      RequestLog.Verdict verdict, String reason) {
        logStore.add(new RequestLog(username == null ? "unknown" : username, action, ip, origin,
                tokenStatus, verdict, reason, appModeLabel()));
    }

    private String appModeLabel() {
        return appMode.get().name();
    }

    private String refererOrigin(HttpServletRequest request) {
        String referer = request.getHeader("Referer");
        if (referer == null) return null;
        try {
            URI uri = URI.create(referer);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            if (scheme == null || host == null) return null;
            return scheme + "://" + host + (port > 0 ? ":" + port : "");
        } catch (Exception e) {
            return null;
        }
    }

    private String safe(String s) { return s == null ? "unknown" : s; }

    private String firstNonBlank(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }
}
