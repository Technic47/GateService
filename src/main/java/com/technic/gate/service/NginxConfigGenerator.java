package com.technic.gate.service;

import com.technic.gate.domain.ProtectedService;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Генерация конфига Nginx под текущий список сервисов.
 *
 * Смысл не в том, чтобы что-то применить автоматически — гейт не имеет доступа к конфигам
 * Nginx и не должен его иметь. Смысл в том, что имя сервиса в заголовке X-Service-Name
 * обязано побайтово совпадать с именем в БД, и набирать его руками второй раз — это
 * ровно то место, где потом полдня ищут опечатку.
 */
@Service
public class NginxConfigGenerator {

    private final int gatePort;

    public NginxConfigGenerator(@Value("${server.port}") int gatePort) {
        this.gatePort = gatePort;
    }

    public String generate(List<ProtectedService> services, String gatePublicUrl) {
        String loginUrl = (gatePublicUrl == null || gatePublicUrl.isBlank())
                ? "https://ВАШ_IP:ПОРТ_ГЕЙТА" : gatePublicUrl.replaceAll("/+$", "");

        StringBuilder sb = new StringBuilder();
        sb.append("# Сгенерировано gate-service. Вставить в конфиг Nginx на VPS.\n");
        sb.append("# Гейт слушает 127.0.0.1:").append(gatePort)
                .append(" — наружу этот порт открывать не нужно.\n\n");

        if (services.isEmpty()) {
            sb.append("# Нет включённых сервисов — добавьте их на странице /admin/services.\n");
            return sb.toString();
        }

        for (ProtectedService service : services) {
            sb.append("# ---------- ").append(service.getDisplayName())
                    .append(" (").append(service.getName()).append(") ----------\n");
            sb.append("server {\n");
            sb.append("    listen 8843 ssl;\n");
            sb.append("    server_name _;\n\n");
            sb.append("    # ssl_certificate     /etc/nginx/ssl/fullchain.pem;\n");
            sb.append("    # ssl_certificate_key /etc/nginx/ssl/privkey.pem;\n\n");

            sb.append("    location = /_gate_verify {\n");
            sb.append("        internal;\n");
            sb.append("        proxy_pass http://127.0.0.1:").append(gatePort).append("/verify;\n");
            sb.append("        proxy_pass_request_body off;\n");
            sb.append("        proxy_set_header Content-Length \"\";\n");
            sb.append("        proxy_set_header X-Service-Name \"").append(service.getName()).append("\";\n");
            sb.append("        proxy_set_header X-Original-URI $request_uri;\n");
            sb.append("        proxy_set_header X-Forwarded-For $remote_addr;\n");
            sb.append("    }\n\n");

            String apiPrefix = service.getApiPrefix();
            if (apiPrefix != null && !apiPrefix.isBlank()) {
                sb.append("    # API (Gate Auth, §5.2): 401/403 — JSON, а не редирект. fetch из SPA пошёл бы\n");
                sb.append("    # по редиректу и получил HTML формы входа; по login_url SPA уводит на вход сама.\n");
                sb.append("    location ").append(apiPrefix).append(" {\n");
                sb.append("        auth_request /_gate_verify;\n");
                appendIdentityHeaders(sb);
                sb.append("        error_page 401 = @gate_api_401;\n");
                sb.append("        error_page 403 = @gate_api_403;\n\n");
                appendProxy(sb, service);
                sb.append("    }\n\n");
            }

            sb.append("    location / {\n");
            sb.append("        auth_request /_gate_verify;\n");
            appendIdentityHeaders(sb);
            sb.append("        # 401 — не вошёл: отправляем на форму логина с возвратом назад.\n");
            sb.append("        error_page 401 = @gate_login;\n");
            sb.append("        # 403 — вошёл, но доступа нет: показываем страницу отказа гейта.\n");
            sb.append("        error_page 403 = @gate_denied;\n\n");
            appendProxy(sb, service);
            sb.append("\n");
            appendLogoutButton(sb, loginUrl);
            sb.append("    }\n\n");

            sb.append("    location @gate_login {\n");
            sb.append("        return 302 ").append(loginUrl)
                    .append("/login?redirect=$scheme://$http_host$request_uri;\n");
            sb.append("    }\n\n");
            sb.append("    location @gate_denied {\n");
            sb.append("        return 302 ").append(loginUrl)
                    .append("/denied?service=").append(service.getName()).append(";\n");
            sb.append("    }\n");
            if (apiPrefix != null && !apiPrefix.isBlank()) {
                sb.append("\n    location @gate_api_401 {\n");
                sb.append("        default_type application/problem+json;\n");
                sb.append("        return 401 '{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401,")
                        .append("\"login_url\":\"").append(loginUrl).append("/login\"}';\n");
                sb.append("    }\n");
                sb.append("    location @gate_api_403 {\n");
                sb.append("        default_type application/problem+json;\n");
                sb.append("        return 403 '{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403}';\n");
                sb.append("    }\n");
            }
            sb.append("}\n\n");
        }

        sb.append("# После правки: nginx -t && systemctl reload nginx\n");
        return sb.toString();
    }

    /**
     * Кто пользователь — для приложения.
     *
     * X-Gate-Assertion — подписанный токен Gate Auth (§5.2): proxy_set_header всегда
     * перезаписывает заголовок, так что прислать свой клиент не может. X-Gate-User — по-старому,
     * для сервисов без библиотеки gate-auth; доверять ему можно только за этим Nginx.
     */
    private static void appendIdentityHeaders(StringBuilder sb) {
        sb.append("        auth_request_set $gate_user $upstream_http_x_gate_user;\n");
        sb.append("        auth_request_set $gate_assertion $upstream_http_x_gate_assertion;\n");
        sb.append("        proxy_set_header X-Gate-User $gate_user;\n");
        sb.append("        proxy_set_header X-Gate-Assertion $gate_assertion;\n\n");
    }

    private static void appendProxy(StringBuilder sb, ProtectedService service) {
        sb.append("        proxy_pass ").append(service.upstreamUrl()).append(";\n");
        sb.append("        proxy_set_header Host $host;\n");
        sb.append("        proxy_set_header X-Real-IP $remote_addr;\n");
        sb.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
        sb.append("        proxy_set_header X-Forwarded-Proto $scheme;\n");
        if ("https".equals(service.getScheme())) {
            sb.append("        # У домашнего Nginx самоподписанный сертификат.\n");
            sb.append("        proxy_ssl_verify off;\n");
        }
        sb.append("        proxy_http_version 1.1;\n");
        sb.append("        proxy_set_header Upgrade $http_upgrade;\n");
        sb.append("        proxy_set_header Connection \"upgrade\";\n");
        sb.append("        proxy_read_timeout 300s;\n");
    }

    /**
     * Кнопка «Выйти» поверх страниц сервиса.
     *
     * Пользователь с одним сервисом после входа попадает сразу в него и интерфейса гейта
     * не видит, а сам сервис про гейт ничего не знает. Nginx дописывает ссылку перед
     * {@code </body>} каждой HTML-страницы. Ссылка, а не форма: POST на другой origin
     * (другой порт) остался бы без CSRF-токена гейта — поэтому она ведёт на страницу
     * подтверждения GET /logout, а выходит уже форма на ней.
     *
     * Без JS, чтобы не спорить с CSP сервиса. Accept-Encoding сбрасывается, потому что
     * sub_filter не умеет работать со сжатым ответом upstream-а и молча его пропускает.
     */
    private static void appendLogoutButton(StringBuilder sb, String gateUrl) {
        sb.append("        # Кнопка «Выйти» поверх страниц сервиса — сам сервис про гейт не знает.\n");
        sb.append("        # Не нужна — удалите эти три строки.\n");
        sb.append("        proxy_set_header Accept-Encoding \"\";\n");
        sb.append("        sub_filter_once on;\n");
        sb.append("        sub_filter '</body>' '<a href=\"").append(gateUrl).append("/logout\" ")
                .append("style=\"position:fixed;right:12px;bottom:12px;z-index:2147483647;")
                .append("padding:6px 12px;border-radius:6px;background:#1f2937;color:#fff;")
                .append("font:13px/1.2 system-ui,sans-serif;text-decoration:none;opacity:.85\">")
                .append("Выйти</a></body>';\n");
    }
}
