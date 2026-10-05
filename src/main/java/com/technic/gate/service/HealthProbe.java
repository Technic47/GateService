package com.technic.gate.service;

import com.technic.gate.domain.ProtectedService;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.springframework.stereotype.Service;

/**
 * Проверка доступности upstream-а обычным TCP-коннектом.
 *
 * Именно TCP, а не HTTP-запрос: у домашнего Nginx самоподписанный сертификат, и HTTPS-клиенту
 * пришлось бы либо отключать проверку сертификата, либо возить truststore. Для вопроса
 * «жив ли SSH-туннель» достаточно того, что порт принимает соединение.
 */
@Service
public class HealthProbe {

    private static final int TIMEOUT_MS = 1500;

    public record Result(boolean reachable, long millis, String error) {

        public static Result up(long millis) {
            return new Result(true, millis, null);
        }

        public static Result down(long millis, String error) {
            return new Result(false, millis, error);
        }
    }

    public Result check(ProtectedService service) {
        return check(service.getHost(), service.getPort());
    }

    public Result check(String host, int port) {
        long started = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            return Result.up(elapsedMs(started));
        } catch (IOException | RuntimeException e) {
            String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return Result.down(elapsedMs(started), message);
        }
    }

    private static long elapsedMs(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }
}
