package com.technic.gate.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Состояние PostgreSQL и потоковой репликации для страницы настроек.
 *
 * Репликация в этом проекте настроена руками и живёт отдельно от приложения, так что
 * выводится она в режиме «только посмотреть». Все запросы обёрнуты в try/catch: отсутствие
 * прав на pg_stat_replication или обрыв связи не должны ронять страницу настроек —
 * она нужна как раз тогда, когда что-то не так.
 */
@Service
public class DatabaseStatusService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseStatusService.class);

    private final JdbcTemplate jdbcTemplate;

    public DatabaseStatusService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public record ReplicaStatus(String clientAddr, String state, String syncState, String lag) {
    }

    public record DbStatus(boolean reachable,
                           String version,
                           boolean inRecovery,
                           List<ReplicaStatus> replicas,
                           String error) {
    }

    public DbStatus status() {
        String version;
        try {
            version = jdbcTemplate.queryForObject("select version()", String.class);
        } catch (RuntimeException e) {
            log.warn("Не удалось получить версию PostgreSQL: {}", e.toString());
            return new DbStatus(false, null, false, List.of(), e.getMessage());
        }

        boolean inRecovery = false;
        try {
            Boolean value = jdbcTemplate.queryForObject("select pg_is_in_recovery()", Boolean.class);
            inRecovery = Boolean.TRUE.equals(value);
        } catch (RuntimeException e) {
            log.debug("pg_is_in_recovery() недоступна: {}", e.toString());
        }

        List<ReplicaStatus> replicas = new ArrayList<>();
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                    select client_addr::text as client_addr,
                           state,
                           sync_state,
                           pg_size_pretty(pg_wal_lsn_diff(sent_lsn, replay_lsn)) as lag
                    from pg_stat_replication
                    """);
            for (Map<String, Object> row : rows) {
                replicas.add(new ReplicaStatus(
                        asString(row.get("client_addr")),
                        asString(row.get("state")),
                        asString(row.get("sync_state")),
                        asString(row.get("lag"))));
            }
        } catch (RuntimeException e) {
            // Нет прав или мы на standby — это не ошибка страницы.
            log.debug("pg_stat_replication недоступна: {}", e.toString());
        }

        return new DbStatus(true, shortVersion(version), inRecovery, replicas, null);
    }

    private static String asString(Object value) {
        return value == null ? "-" : value.toString();
    }

    /** "PostgreSQL 16.4 on x86_64..." -> "PostgreSQL 16.4" */
    private static String shortVersion(String full) {
        if (full == null) {
            return null;
        }
        int on = full.indexOf(" on ");
        return on > 0 ? full.substring(0, on) : full;
    }
}
