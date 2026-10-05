package com.technic.gate.domain;

/**
 * Типы событий журнала активности.
 *
 * Категория нужна, чтобы страница журнала фильтровала по смыслу события,
 * а не по длинному плоскому списку типов.
 */
public enum ActivityType {
    LOGIN_SUCCESS(Category.AUTH),
    LOGIN_FAILURE(Category.AUTH),
    LOGOUT(Category.AUTH),
    REGISTER(Category.AUTH),
    ACCOUNT_LOCKED(Category.AUTH),

    VERIFY_ALLOWED(Category.ACCESS),
    VERIFY_DENIED(Category.ACCESS),
    SERVICE_OPENED(Category.ACCESS),

    USER_CREATED(Category.ADMIN),
    USER_UPDATED(Category.ADMIN),
    USER_DELETED(Category.ADMIN),
    USER_BLOCKED(Category.ADMIN),
    USER_UNBLOCKED(Category.ADMIN),
    PASSWORD_RESET(Category.ADMIN),
    ACCESS_GRANTED(Category.ADMIN),
    ACCESS_REVOKED(Category.ADMIN),
    SERVICE_CREATED(Category.ADMIN),
    SERVICE_UPDATED(Category.ADMIN),
    SERVICE_DELETED(Category.ADMIN),
    SETTINGS_UPDATED(Category.ADMIN);

    public enum Category { AUTH, ACCESS, ADMIN }

    private final Category category;

    ActivityType(Category category) {
        this.category = category;
    }

    public Category getCategory() {
        return category;
    }
}
