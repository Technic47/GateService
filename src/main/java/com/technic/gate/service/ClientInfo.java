package com.technic.gate.service;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Извлечение данных о клиенте из запроса.
 *
 * Гейт всегда стоит за Nginx, поэтому remoteAddr — это адрес самого Nginx.
 * Реальный адрес берётся из X-Forwarded-For (первый элемент цепочки).
 * Заголовку можно доверять только потому, что снаружи до сервиса не достучаться:
 * порт гейта не должен быть открыт в интернет, только на localhost VPS.
 */
public final class ClientInfo {

    private ClientInfo() {
    }

    public static String ip(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            String first = (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
            if (!first.isEmpty()) {
                return truncate(first, 64);
            }
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return truncate(realIp.trim(), 64);
        }
        return truncate(request.getRemoteAddr(), 64);
    }

    public static String userAgent(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        return truncate(request.getHeader("User-Agent"), 256);
    }

    public static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
