package com.technic.gate.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Проверка адресов, на которые гейт готов отправить браузер.
 *
 * Параметр redirect приходит из URL, и ссылку с ним может прислать кто угодно. Проверять его
 * сравнением строк нельзя: {@code "https://144.31.187.7:8843@evil.com/".startsWith(publicUrl)}
 * истинно, а браузер считает всё до {@code @} логином и уходит на evil.com — сразу после того,
 * как пользователь ввёл пароль на настоящем гейте. Поэтому адрес разбирается на части,
 * и схема, хост, порт и путь сравниваются по отдельности.
 *
 * Разбор через {@link URI} строже браузерного: обратный слеш, пробелы, управляющие символы
 * в нём недопустимы. Всё, что не разобралось, отвергается — это и нужно: браузеры трактуют
 * {@code /\evil.com} и {@code /<TAB>/evil.com} как {@code //evil.com}, то есть как чужой хост.
 */
public final class RedirectTargets {

    private RedirectTargets() {
    }

    /**
     * Относительный путь внутри гейта: {@code /portal}, {@code /admin/users?page=2}.
     * Не принимает {@code //host} (протокол-относительный URL — это уже чужой хост),
     * обратные слеши и управляющие символы.
     */
    public static boolean isLocalPath(String value) {
        if (value == null || value.isEmpty() || value.charAt(0) != '/') {
            return false;
        }
        if (value.startsWith("//") || hasForbiddenChars(value)) {
            return false;
        }
        URI uri = parse(value);
        return uri != null && uri.getScheme() == null && uri.getRawAuthority() == null;
    }

    /**
     * Абсолютный адрес, лежащий внутри публичного адреса сервиса: та же схема, тот же хост,
     * тот же порт, путь совпадает с путём сервиса или вложен в него, логина/пароля в адресе нет.
     */
    public static boolean isWithin(String candidate, String baseUrl) {
        if (candidate == null || baseUrl == null || hasForbiddenChars(candidate)) {
            return false;
        }
        URI target = parse(candidate);
        URI base = parse(baseUrl.trim());
        if (target == null || base == null || !isHierarchicalWithHost(target)
                || !isHierarchicalWithHost(base)) {
            return false;
        }
        if (target.getRawUserInfo() != null) {
            return false;
        }
        if (!target.getScheme().equalsIgnoreCase(base.getScheme())
                || !target.getHost().equalsIgnoreCase(base.getHost())
                || effectivePort(target) != effectivePort(base)) {
            return false;
        }
        return isPathWithin(target.normalize().getRawPath(), base.normalize().getRawPath());
    }

    private static boolean isPathWithin(String path, String basePath) {
        String prefix = basePath == null ? "" : basePath.replaceAll("/+$", "");
        if (prefix.isEmpty()) {
            return true;
        }
        String actual = path == null ? "" : path;
        // Сравнение по границе сегмента: /app не должен пропускать /application.
        return actual.equals(prefix) || actual.startsWith(prefix + "/");
    }

    private static boolean isHierarchicalWithHost(URI uri) {
        if (!uri.isAbsolute() || uri.isOpaque() || uri.getHost() == null) {
            return false;
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        return scheme.equals("https") || scheme.equals("http");
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static boolean hasForbiddenChars(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c < 0x20 || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    private static URI parse(String value) {
        try {
            return new URI(value);
        } catch (URISyntaxException e) {
            return null;
        }
    }
}
