package com.technic.gate.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class RedirectTargetsTest {

    private static final String FASHIONMARK = "https://144.31.187.7:8843";

    @ParameterizedTest
    @ValueSource(strings = {
            "/portal",
            "/admin/users?page=2",
            "/admin/activity?user=admin&type=LOGIN_FAILURE",
            "/%2F%2Fevil.com"
    })
    void acceptsPathsInsideGate(String value) {
        assertTrue(RedirectTargets.isLocalPath(value), value);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "portal",
            "//evil.com",
            "/\\evil.com",
            "\\/evil.com",
            "/\t/evil.com",
            "/\n/evil.com",
            "/portal\r\nSet-Cookie: x=1",
            "https://evil.com/",
            "javascript:alert(1)"
    })
    void rejectsPathsLeavingGate(String value) {
        assertFalse(RedirectTargets.isLocalPath(value), String.valueOf(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://144.31.187.7:8843",
            "https://144.31.187.7:8843/",
            "https://144.31.187.7:8843/catalog/42?sort=price",
            "HTTPS://144.31.187.7:8843/"
    })
    void acceptsUrlsInsideService(String value) {
        assertTrue(RedirectTargets.isWithin(value, FASHIONMARK), value);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            // Всё до @ браузер считает логином и уходит на evil.com — ради этого класс и написан.
            "https://144.31.187.7:8843@evil.com/",
            "https://144.31.187.7:8843@evil.com:8843/",
            "https://user:pass@144.31.187.7:8843/",
            "https://144.31.187.7:8843\\@evil.com/",
            "https://144.31.187.7:8843.evil.com/",
            "https://144.31.187.7:88430/",
            "https://144.31.187.7:9001/",
            "https://144.31.187.7/",
            "http://144.31.187.7:8843/",
            "//144.31.187.7:8843/",
            "/portal",
            "https:144.31.187.7:8843",
            "https://144.31.187.7:8843/\t/evil.com",
            "javascript://144.31.187.7:8843/%0aalert(1)"
    })
    void rejectsUrlsOutsideService(String value) {
        assertFalse(RedirectTargets.isWithin(value, FASHIONMARK), String.valueOf(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://example.org/app",
            "https://example.org/app/",
            "https://example.org/app/page",
            "https://example.org:443/app/page"
    })
    void acceptsUrlsUnderServicePath(String value) {
        assertTrue(RedirectTargets.isWithin(value, "https://example.org/app/"), value);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://example.org/application",
            "https://example.org/",
            "https://example.org/app/../admin"
    })
    void rejectsUrlsOutsideServicePath(String value) {
        assertFalse(RedirectTargets.isWithin(value, "https://example.org/app"), value);
    }
}
