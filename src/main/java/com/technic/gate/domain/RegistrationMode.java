package com.technic.gate.domain;

public enum RegistrationMode {
    /** Любой может зарегистрироваться и сразу войти. */
    OPEN("Открытая — вход сразу после регистрации"),
    /** Регистрация доступна, но аккаунт неактивен до одобрения администратором. */
    APPROVAL("С одобрением — админ подтверждает каждый новый аккаунт"),
    /** Форма регистрации скрыта; аккаунты заводит только админ. */
    CLOSED("Закрытая — аккаунты создаёт только админ");

    private final String label;

    RegistrationMode(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
