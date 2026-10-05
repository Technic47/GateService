package com.technic.gate.domain;

public enum Role {
    ADMIN,
    USER;

    /** Spring Security ждёт префикс ROLE_ для hasRole(). */
    public String authority() {
        return "ROLE_" + name();
    }
}
