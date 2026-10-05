package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Настройка гейта в виде ключ/значение.
 *
 * Плоская таблица, а не колонки в единственной строке: набор настроек будет меняться,
 * а добавление ключа не должно тянуть за собой миграцию схемы. Типизация и значения
 * по умолчанию живут в GateSettings/GateSettingsService.
 */
@Entity
@Table(name = "gate_settings")
public class GateSetting {

    @Id
    @Column(name = "setting_key", length = 64)
    private String key;

    @Column(name = "setting_value", length = 1024)
    private String value;

    protected GateSetting() {
    }

    public GateSetting(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() { return key; }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}
