package com.csrfshield.controller;

import com.csrfshield.model.RequestLog;
import com.csrfshield.security.AppMode;
import com.csrfshield.security.AuthHelper;
import com.csrfshield.store.LogStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DashboardApiController {

    private final LogStore logStore;
    private final AppMode appMode;
    private final AuthHelper authHelper;

    public DashboardApiController(LogStore logStore, AppMode appMode, AuthHelper authHelper) {
        this.logStore = logStore;
        this.appMode = appMode;
        this.authHelper = authHelper;
    }

    @GetMapping("/logs")
    public Map<String, Object> logs(HttpServletRequest request) {
        if (!authHelper.isAuthenticated(request)) return Map.of("error", "unauthenticated");
        List<RequestLog> all = logStore.getAll();
        return Map.of(
                "valid", logStore.getValid(),
                "suspicious", logStore.getSuspicious(),
                "trend", logStore.getSuspiciousTrend(),
                "total", all.size(),
                "mode", appMode.get()
        );
    }

    @PostMapping("/mode/toggle")
    public Map<String, Object> toggleMode(HttpServletRequest request) {
        if (!authHelper.isAuthenticated(request)) return Map.of("error", "unauthenticated");
        AppMode.Mode m = appMode.toggle();
        return Map.of("mode", m);
    }

    @GetMapping("/logs/export")
    public void exportCsv(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (!authHelper.isAuthenticated(request)) {
            response.setStatus(401);
            return;
        }
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=csrf-shield-logs.csv");
        PrintWriter writer = response.getWriter();
        writer.println("RequestID,Timestamp,Username,Action,IP,Origin,TokenStatus,Verdict,Reason,Mode");
        for (RequestLog l : logStore.getAll()) {
            writer.printf("%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",%s%n",
                    l.getRequestId(), l.getTimestamp(), l.getUsername(), l.getAction(),
                    l.getIp(), l.getOrigin(), l.getTokenStatus(), l.getVerdict(),
                    l.getReason().replace("\"", "'"), l.getMode());
        }
        writer.flush();
    }
}
