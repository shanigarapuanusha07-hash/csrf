package com.csrfshield.controller;

import com.csrfshield.model.SessionInfo;
import com.csrfshield.security.CookieUtil;
import com.csrfshield.security.CsrfTokenManager;
import com.csrfshield.store.SessionStore;
import com.csrfshield.store.UserStore;
import com.csrfshield.util.RequestUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Controller
public class AuthController {

    private final UserStore userStore;
    private final SessionStore sessionStore;
    private final CsrfTokenManager tokenManager;
    private final CookieUtil cookieUtil;

    private static final int SESSION_MAX_AGE = 60 * 30; // 30 minutes

    public AuthController(UserStore userStore, SessionStore sessionStore,
                           CsrfTokenManager tokenManager, CookieUtil cookieUtil) {
        this.userStore = userStore;
        this.sessionStore = sessionStore;
        this.tokenManager = tokenManager;
        this.cookieUtil = cookieUtil;
    }

    @GetMapping("/login")
    public String loginPage(Model model, @RequestParam(required = false) String error) {
        model.addAttribute("error", error);
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                         HttpServletRequest request, HttpServletResponse response) {

        if (!userStore.checkPassword(username, password)) {
            return "redirect:/login?error=Invalid+username+or+password";
        }

        String sessionId = UUID.randomUUID().toString();
        String ip = RequestUtil.clientIp(request);
        String userAgent = request.getHeader("User-Agent");

        SessionInfo session = new SessionInfo(sessionId, username, ip, userAgent);
        String token = tokenManager.issueToken(session);
        sessionStore.put(sessionId, session);

        // Secure, HttpOnly, SameSite session-identity cookie
        cookieUtil.setSessionCookie(response, sessionId, SESSION_MAX_AGE);
        // CSRF token cookie (double-submit style, readable by client JS/forms)
        cookieUtil.setCsrfCookie(response, token, (int) tokenManager.getExpirySeconds());

        return "redirect:/dashboard";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = RequestUtil.cookieValue(request, CookieUtil.SESSION_COOKIE);
        sessionStore.invalidate(sessionId);
        cookieUtil.clearCookie(response, CookieUtil.SESSION_COOKIE);
        cookieUtil.clearCookie(response, "CSRF_TOKEN");
        return "redirect:/login";
    }
}
