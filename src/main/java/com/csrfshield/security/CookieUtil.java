package com.csrfshield.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The classic jakarta.servlet.http.Cookie class has no setSameSite() method,
 * so to actually control HttpOnly + Secure + SameSite together we build the
 * Set-Cookie header by hand and add it directly to the response.
 *
 * The SameSite attribute is deliberately tied to {@link AppMode}: in DEFENSE
 * mode cookies use SameSite=Strict (the real recommended setting). In ATTACK
 * mode they are reissued with SameSite=None; Secure, to simulate an
 * application that never adopted SameSite cookies at all -- letting the
 * Attack Lab's cross-site auto-submit form actually reach the server with
 * cookies attached, the way it would against a genuinely unprotected app.
 * (Chrome/Edge treat http://localhost as a secure context, so Secure
 * cookies still work there for this demo without HTTPS.)
 */
@Component
public class CookieUtil {

    @Value("${csrf.cookies.secure:false}")
    private boolean secureCookies;

    public static final String SESSION_COOKIE = "SHIELD_SESSION";

    private final AppMode appMode;

    public CookieUtil(AppMode appMode) {
        this.appMode = appMode;
    }

    /** Session identity cookie: HttpOnly (JS can't read it), SameSite driven by current mode. */
    public void setSessionCookie(HttpServletResponse response, String sessionId, int maxAgeSeconds) {
        addCookieHeader(response, SESSION_COOKIE, sessionId, maxAgeSeconds, true, currentSameSite(), currentSecure());
    }

    /**
     * The CSRF token itself is deliberately NOT HttpOnly for the classic
     * synchronizer-token pattern: client-side JS/forms need to read it so
     * they can echo it back in a hidden field or custom header. Its
     * unforgeability comes from the HMAC signature + session binding, not
     * from secrecy of transport.
     */
    public void setCsrfCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        addCookieHeader(response, "CSRF_TOKEN", token, maxAgeSeconds, false, currentSameSite(), currentSecure());
    }

    private String currentSameSite() {
        return appMode.isDefenseMode() ? "Strict" : "None";
    }

    private boolean currentSecure() {
        // SameSite=None requires Secure. Otherwise, use the configured value.
        return appMode.isDefenseMode() ? secureCookies : true;
    }

    public void clearCookie(HttpServletResponse response, String name) {
        addCookieHeader(response, name, "", 0, true, "Strict", secureCookies);
    }

    private void addCookieHeader(HttpServletResponse response, String name, String value,
                                  int maxAgeSeconds, boolean httpOnly, String sameSite, boolean secure) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value)
          .append("; Path=/")
          .append("; Max-Age=").append(maxAgeSeconds)
          .append("; SameSite=").append(sameSite);
        if (httpOnly) sb.append("; HttpOnly");
        if (secure) sb.append("; Secure");
        response.addHeader("Set-Cookie", sb.toString());
    }
}
