package com.csrfshield.controller;

import com.csrfshield.model.SessionInfo;
import com.csrfshield.model.User;
import com.csrfshield.security.AuthHelper;
import com.csrfshield.security.CookieUtil;
import com.csrfshield.security.CsrfTokenManager;
import com.csrfshield.store.UserStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * NOTE: this endpoint's request never reaches here unless CsrfFilter already
 * let it through (see CsrfFilter.PROTECTED_PATHS) - the filter is where the
 * actual CSRF enforcement happens. This controller only performs the action.
 */
@Controller
public class ProfileController {

    private final AuthHelper authHelper;
    private final UserStore userStore;
    private final CsrfTokenManager tokenManager;
    private final CookieUtil cookieUtil;

    public ProfileController(AuthHelper authHelper, UserStore userStore,
                              CsrfTokenManager tokenManager, CookieUtil cookieUtil) {
        this.authHelper = authHelper;
        this.userStore = userStore;
        this.tokenManager = tokenManager;
        this.cookieUtil = cookieUtil;
    }

    @PostMapping("/profile/update")
    public String updateProfile(@RequestParam String email,
                                 HttpServletRequest request, HttpServletResponse response) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";

        User user = userStore.find(session.getUsername());
        user.setEmail(email);

        // Rotate the token after a successful sensitive action (defense-in-depth
        // against token replay).
        String newToken = tokenManager.issueToken(session);
        cookieUtil.setCsrfCookie(response, newToken, (int) tokenManager.getExpirySeconds());

        return "redirect:/profile?updated=1";
    }
}
