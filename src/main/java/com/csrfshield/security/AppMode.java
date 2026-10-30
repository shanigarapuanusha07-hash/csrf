package com.csrfshield.security;

import org.springframework.stereotype.Component;

/**
 * Global toggle used ONLY to power the classroom-style demonstration:
 *
 *  DEFENSE (default) - CsrfFilter fully enforces token / origin / header checks.
 *  ATTACK            - CsrfFilter skips its checks, so the same malicious
 *                       auto-submit form that fails in Defense mode will
 *                       silently succeed, proving the vulnerability it
 *                       otherwise blocks.
 *
 * This is intentionally a single in-memory flag shared by the whole app --
 * it exists to let a demo audience flip a switch and see the difference,
 * not to model a real multi-tenant setting.
 */
@Component
public class AppMode {

    public enum Mode { DEFENSE, ATTACK }

    private volatile Mode mode = Mode.DEFENSE;

    public Mode get() { return mode; }

    public boolean isDefenseMode() { return mode == Mode.DEFENSE; }

    public Mode toggle() {
        mode = (mode == Mode.DEFENSE) ? Mode.ATTACK : Mode.DEFENSE;
        return mode;
    }

    public void set(Mode m) { this.mode = m; }
}
