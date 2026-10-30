package com.csrfshield.controller;

import com.csrfshield.model.SessionInfo;
import com.csrfshield.security.AppMode;
import com.csrfshield.security.AuthHelper;
import com.csrfshield.security.CookieUtil;
import com.csrfshield.store.UserStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    private final AuthHelper authHelper;
    private final UserStore userStore;
    private final AppMode appMode;
    private final CookieUtil cookieUtil;

    public PageController(AuthHelper authHelper, UserStore userStore, AppMode appMode, CookieUtil cookieUtil) {
        this.authHelper = authHelper;
        this.userStore = userStore;
        this.appMode = appMode;
        this.cookieUtil = cookieUtil;
    }

    /**
     * Re-issues the session + CSRF cookies with attributes matching the
     * CURRENT AppMode (see CookieUtil). This lets toggling Attack/Defense
     * mode in the Attack Lab take effect immediately on the next page load,
     * without forcing the user to log in again.
     */
    private void refreshCookiesForCurrentMode(SessionInfo session, HttpServletResponse response) {
        cookieUtil.setSessionCookie(response, session.getSessionId(), 60 * 30);
        if (session.getCsrfToken() != null) {
            cookieUtil.setCsrfCookie(response, session.getCsrfToken(), 60 * 30);
        }
    }

    @GetMapping("/")
    public String root(HttpServletRequest request) {
        return authHelper.isAuthenticated(request) ? "redirect:/dashboard" : "redirect:/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, HttpServletResponse response, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";
        refreshCookiesForCurrentMode(session, response);
        model.addAttribute("username", session.getUsername());
        model.addAttribute("csrfToken", session.getCsrfToken());
        model.addAttribute("balance", userStore.find(session.getUsername()).getBalance());
        model.addAttribute("mode", appMode.get());
        return "dashboard";
    }

    @GetMapping("/profile")
    public String profilePage(HttpServletRequest request, HttpServletResponse response, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";
        refreshCookiesForCurrentMode(session, response);
        model.addAttribute("username", session.getUsername());
        model.addAttribute("email", userStore.find(session.getUsername()).getEmail());
        model.addAttribute("csrfToken", session.getCsrfToken());
        return "profile";
    }

    @GetMapping("/password")
    public String passwordPage(HttpServletRequest request, HttpServletResponse response, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";
        refreshCookiesForCurrentMode(session, response);
        model.addAttribute("username", session.getUsername());
        model.addAttribute("csrfToken", session.getCsrfToken());
        return "password";
    }

    @GetMapping("/transfer")
    public String transferPage(HttpServletRequest request, HttpServletResponse response, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";
        refreshCookiesForCurrentMode(session, response);
        model.addAttribute("username", session.getUsername());
        model.addAttribute("balance", userStore.find(session.getUsername()).getBalance());
        model.addAttribute("csrfToken", session.getCsrfToken());
        return "transfer";
    }

    @GetMapping("/security-dashboard")
    public String securityDashboard(HttpServletRequest request, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";
        model.addAttribute("username", session.getUsername());
        model.addAttribute("mode", appMode.get());
        return "security-dashboard";
    }

    @GetMapping("/attack")
    public String attackPage(HttpServletRequest request, HttpServletResponse response, Model model) {
        SessionInfo session = authHelper.currentSession(request);
        model.addAttribute("loggedIn", session != null);
        if (session != null) {
            refreshCookiesForCurrentMode(session, response);
            model.addAttribute("username", session.getUsername());
        }
        model.addAttribute("mode", appMode.get());
        return "attack";
    }

    @GetMapping("/integration")
    public String integrationPage() {
        return "integration";
    }
}
