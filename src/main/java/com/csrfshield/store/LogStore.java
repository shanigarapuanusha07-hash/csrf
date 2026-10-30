package com.csrfshield.store;

import com.csrfshield.model.RequestLog;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class LogStore {

    private final List<RequestLog> logs = new CopyOnWriteArrayList<>();
    // tracks consecutive failed attempts per (ip+username) so the dashboard
    // can flag "repeated failed attempts" as its own suspicious signal
    private final Map<String, Integer> failureCounters = new ConcurrentHashMap<>();

    public void add(RequestLog log) {
        logs.add(0, log); // newest first
        if (logs.size() > 500) {
            logs.remove(logs.size() - 1);
        }
        String key = log.getIp() + "|" + log.getUsername();
        if (log.getVerdict() == RequestLog.Verdict.SUSPICIOUS) {
            failureCounters.merge(key, 1, Integer::sum);
        } else {
            failureCounters.remove(key);
        }
    }

    public int getFailureCount(String ip, String username) {
        return failureCounters.getOrDefault(ip + "|" + username, 0);
    }

    public List<RequestLog> getAll() {
        return Collections.unmodifiableList(logs);
    }

    public List<RequestLog> getValid() {
        return logs.stream().filter(l -> l.getVerdict() == RequestLog.Verdict.VALID).toList();
    }

    public List<RequestLog> getSuspicious() {
        return logs.stream().filter(l -> l.getVerdict() == RequestLog.Verdict.SUSPICIOUS).toList();
    }

    /** Suspicious-activity counts bucketed by minute, for the trend graph. */
    public Map<String, Long> getSuspiciousTrend() {
        Map<String, Long> trend = new LinkedHashMap<>();
        List<RequestLog> suspicious = new ArrayList<>(getSuspicious());
        Collections.reverse(suspicious); // oldest first for a left-to-right timeline
        for (RequestLog l : suspicious) {
            String bucket = l.getTimestamp().toString().substring(11, 16); // HH:mm
            trend.merge(bucket, 1L, Long::sum);
        }
        return trend;
    }

    public void clear() {
        logs.clear();
        failureCounters.clear();
    }
}
