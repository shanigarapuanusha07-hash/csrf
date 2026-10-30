package com.csrfshield.store;

import com.csrfshield.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory user "database" seeded with demo accounts.
 * Not a real persistence layer -- this project's focus is CSRF defense,
 * not user management.
 */
@Component
public class UserStore {

    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public UserStore() {
        users.put("alice", new User("alice", encoder.encode("password123"), 5000.00, "alice@example.com"));
        users.put("bob", new User("bob", encoder.encode("password123"), 1200.50, "bob@example.com"));
    }

    public User find(String username) {
        return users.get(username);
    }

    public boolean checkPassword(String username, String rawPassword) {
        User u = users.get(username);
        return u != null && encoder.matches(rawPassword, u.getPasswordHash());
    }

    public BCryptPasswordEncoder getEncoder() {
        return encoder;
    }
}
