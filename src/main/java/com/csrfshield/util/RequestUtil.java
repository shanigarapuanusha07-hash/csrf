package com.csrfshield.util;

import jakarta.servlet.http.HttpServletRequest;

public final class RequestUtil {
    private RequestUtil() {}

    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public static String cookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (var c : request.getCookies()) {
            if (c.getName().equals(name)) return c.getValue();
        }
        return null;
    }
}
