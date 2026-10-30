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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class TransferController {

    private final AuthHelper authHelper;
    private final UserStore userStore;
    private final CsrfTokenManager tokenManager;
    private final CookieUtil cookieUtil;

    public TransferController(AuthHelper authHelper, UserStore userStore,
                               CsrfTokenManager tokenManager, CookieUtil cookieUtil) {
        this.authHelper = authHelper;
        this.userStore = userStore;
        this.tokenManager = tokenManager;
        this.cookieUtil = cookieUtil;
    }

    /** Classic form-submission transfer -- this is the endpoint the attack-simulation page targets. */
    @PostMapping("/transfer")
    public String transfer(@RequestParam String toAccount, @RequestParam double amount,
                            HttpServletRequest request, HttpServletResponse response) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) return "redirect:/login";

        applyTransfer(session.getUsername(), toAccount, amount);

        String newToken = tokenManager.issueToken(session);
        cookieUtil.setCsrfCookie(response, newToken, (int) tokenManager.getExpirySeconds());

        return "redirect:/transfer?done=1&to=" + toAccount + "&amt=" + amount;
    }

    /** AJAX/JSON variant -- requires the X-Requested-With + X-CSRF-Token custom headers. */
    @PostMapping("/api/transfer")
    @ResponseBody
    public Map<String, Object> transferJson(@RequestBody Map<String, Object> body,
                                             HttpServletRequest request, HttpServletResponse response) {
        SessionInfo session = authHelper.currentSession(request);
        if (session == null) {
            response.setStatus(401);
            return Map.of("error", "not authenticated");
        }

        String toAccount = String.valueOf(body.get("toAccount"));
        double amount = Double.parseDouble(String.valueOf(body.get("amount")));
        applyTransfer(session.getUsername(), toAccount, amount);

        String newToken = tokenManager.issueToken(session);
        cookieUtil.setCsrfCookie(response, newToken, (int) tokenManager.getExpirySeconds());

        return Map.of("status", "success", "newToken", newToken,
                "newBalance", userStore.find(session.getUsername()).getBalance());
    }

    private void applyTransfer(String fromUsername, String toAccount, double amount) {
        User from = userStore.find(fromUsername);
        if (from != null && amount > 0 && from.getBalance() >= amount) {
            from.setBalance(from.getBalance() - amount);
        }
    }
}
