package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Защищаемый гейтом сервис.
 *
 * Про адреса — их два, и они про разное:
 *  - host/port  — где сервис живёт с точки зрения VPS (upstream). Для FashionMark это
 *                 127.0.0.1:8080, вход в SSH-туннель. Отсюда берётся проверка доступности
 *                 и генерация конфига Nginx.
 *  - publicUrl  — куда гейт отправляет браузер пользователя после логина, то есть публичный
 *                 адрес через Nginx (https://144.31.187.7:8843).
 *
 * Смешивать нельзя: у браузера нет доступа к 127.0.0.1 на VPS.
 */
@Entity
@Table(name = "services")
public class ProtectedService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Машинное имя. Именно оно приходит от Nginx в заголовке X-Service-Name. */
    @Column(nullable = false, unique = true, length = 64)
    private String name;

    @Column(name = "display_name", nullable = false, length = 128)
    private String displayName;

    @Column(length = 512)
    private String description;

    /** Схема upstream-а: http или https (у домашнего Nginx самоподписанный https). */
    @Column(nullable = false, length = 8)
    private String scheme = "http";

    @Column(nullable = false, length = 255)
    private String host = "127.0.0.1";

    @Column(nullable = false)
    private int port = 8080;

    @Column(name = "public_url", length = 512)
    private String publicUrl;

    @Column(nullable = false)
    private boolean enabled = true;

    /** Эмодзи для плитки на странице выбора сервиса. Косметика. */
    @Column(length = 8)
    private String icon;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder = 0;

    protected ProtectedService() {
    }

    public ProtectedService(String name, String displayName, String host, int port) {
        this.name = name;
        this.displayName = displayName;
        this.host = host;
        this.port = port;
    }

    /** Адрес upstream-а: для конфига Nginx и для проверки доступности. */
    public String upstreamUrl() {
        return scheme + "://" + host + ":" + port;
    }

    /** Куда вести браузер. Если публичный URL не задан — падаем на upstream. */
    public String targetUrl() {
        return (publicUrl != null && !publicUrl.isBlank()) ? publicUrl : upstreamUrl();
    }

    public Long getId() { return id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getScheme() { return scheme; }
    public void setScheme(String scheme) { this.scheme = scheme; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public String getPublicUrl() { return publicUrl; }
    public void setPublicUrl(String publicUrl) { this.publicUrl = publicUrl; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getIcon() { return icon; }
    public void setIcon(String icon) { this.icon = icon; }

    public int getSortOrder() { return sortOrder; }
    public void setSortOrder(int sortOrder) { this.sortOrder = sortOrder; }

    /**
     * Равенство по идентификатору, а не по ссылке.
     *
     * Иначе Set<ProtectedService> у пользователя и список сервисов из отдельного запроса
     * состояли бы из разных экземпляров одной строки, и contains() всегда возвращал бы false —
     * в админке галочки выданных доступов просто не проставлялись бы.
     * Непрогруженная сущность (id == null) не равна ничему, включая другую непрогруженную.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ProtectedService that)) {
            return false;
        }
        return id != null && id.equals(that.id);
    }

    /**
     * Константа по классу — обязательное условие для сущности с генерируемым id:
     * hashCode не должен меняться, когда после сохранения у объекта появляется id,
     * иначе объект теряется в уже существующем HashSet.
     */
    @Override
    public int hashCode() {
        return ProtectedService.class.hashCode();
    }
}
