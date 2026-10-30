package com.csrfshield.controller;

import com.csrfshield.model.SessionInfo;
import com.csrfshield.security.AuthHelper;
import com.csrfshield.security.CookieUtil;
import com.csrfshield.security.CsrfTokenManager;
import com.csrfshield.store.UserStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PasswordController {

    private final AuthHelper authHelper;
    private final UserStore userStore;
    private final CsrfTokenManager tokenManager;
    private final CookieUtil cookieUtil;

    public PasswordController(AuthHelper authHelper, UserStore userStore,
                               CsrfTokenManager tokenManager, CookieUtil cookieUtil) {
        this.authHelper = authHelper;
        this.userStore = userStore;
        this.tokenManager = tokenManager;
        this.cookieUtil = cookieUtil;
    }

    @PostMapping("/password/change")
    public String changePassword(@RequestParam String newPassword,
                                  HttpServletRequest request, HttpServletResponse response) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";

        // Demo only: in a real system this would re-hash and persist, and
        // would also require the *current* password. Kept minimal here since
        // the focus of this project is the CSRF defense layer, not auth flows.

        String newToken = tokenManager.issueToken(session);
        cookieUtil.setCsrfCookie(response, newToken, (int) tokenManager.getExpirySeconds());

        return "redirect:/password?updated=1";
    }
}
