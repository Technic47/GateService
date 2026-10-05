package com.technic.gate.service;

import com.technic.gate.domain.ActivityLog;
import com.technic.gate.domain.ActivityType;
import com.technic.gate.repo.ActivityLogRepository;
import jakarta.persistence.criteria.Predicate;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Журнал активности пользователей.
 *
 * Пишет в два места сразу:
 *  - таблица activity_log — источник для страницы /admin/activity (фильтры, история);
 *  - логгер gate.activity одной строкой на событие — это то, что видно в docker logs
 *    и, если он поднят, в Dozzle.
 *
 * Запись журнала не должна ронять то, что журналируется: всё обёрнуто в try/catch,
 * а транзакция всегда новая (REQUIRES_NEW), чтобы упавшая вставка не пометила
 * внешнюю транзакцию как rollback-only.
 */
@Service
public class ActivityService {

    /** Отдельный логгер: в logback ему можно задать свой файл/формат, не трогая остальные. */
    private static final Logger activityLog = LoggerFactory.getLogger("gate.activity");
    private static final Logger log = LoggerFactory.getLogger(ActivityService.class);

    private final ActivityLogRepository repository;
    private final ActivityWriter writer;

    public ActivityService(ActivityLogRepository repository, ActivityWriter writer) {
        this.repository = repository;
        this.writer = writer;
    }

    public Builder event(ActivityType type) {
        return new Builder(type);
    }

    @Transactional(readOnly = true)
    public Page<ActivityLog> search(ActivityFilter filter, Pageable pageable) {
        return repository.findAll(toSpecification(filter), pageable);
    }

    @Transactional(readOnly = true)
    public List<ActivityLog> recentFor(String username) {
        return repository.findTop20ByUsernameOrderByAtDesc(username);
    }

    @Transactional(readOnly = true)
    public long countSince(Instant since) {
        return repository.countByAtAfter(since);
    }

    @Transactional(readOnly = true)
    public long countFailuresSince(Instant since) {
        return repository.countFailuresSince(since);
    }

    /** Удаляет записи старше срока хранения. Вызывается по расписанию. */
    @Transactional
    public int purgeOlderThan(int retentionDays) {
        if (retentionDays <= 0) {
            return 0;
        }
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        int removed = repository.deleteOlderThan(cutoff);
        if (removed > 0) {
            log.info("Журнал активности: удалено {} записей старше {}", removed, cutoff);
        }
        return removed;
    }

    private Specification<ActivityLog> toSpecification(ActivityFilter filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (filter.username() != null && !filter.username().isBlank()) {
                predicates.add(cb.like(
                        cb.lower(root.get("username")),
                        "%" + filter.username().toLowerCase() + "%"));
            }
            if (filter.type() != null) {
                predicates.add(cb.equal(root.get("type"), filter.type()));
            }
            if (filter.category() != null) {
                predicates.add(cb.equal(root.get("category"), filter.category()));
            }
            if (filter.serviceName() != null && !filter.serviceName().isBlank()) {
                predicates.add(cb.equal(root.get("serviceName"), filter.serviceName()));
            }
            if (filter.onlyFailures()) {
                predicates.add(cb.isFalse(root.get("success")));
            }
            if (filter.from() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("at"), filter.from()));
            }
            if (filter.to() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("at"), filter.to()));
            }
            return predicates.isEmpty() ? null : cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    /** Критерии фильтрации для страницы журнала. Любое поле может быть null. */
    public record ActivityFilter(
            String username,
            ActivityType type,
            ActivityType.Category category,
            String serviceName,
            boolean onlyFailures,
            Instant from,
            Instant to) {

        public static ActivityFilter empty() {
            return new ActivityFilter(null, null, null, null, false, null, null);
        }
    }

    /** Сборка записи журнала. Ничего не пишет, пока не вызван save(). */
    public final class Builder {

        private final ActivityLog entry;

        private Builder(ActivityType type) {
            this.entry = new ActivityLog(type, null, null);
        }

        public Builder user(String username, Long userId) {
            entry.setUsername(ClientInfo.truncate(username, 64));
            entry.setUserId(userId);
            return this;
        }

        public Builder user(com.technic.gate.domain.User user) {
            return user == null ? this : user(user.getUsername(), user.getId());
        }

        public Builder service(String serviceName) {
            entry.setServiceName(ClientInfo.truncate(serviceName, 64));
            return this;
        }

        public Builder detail(String detail) {
            entry.setDetail(ClientInfo.truncate(detail, 512));
            return this;
        }

        public Builder failed() {
            entry.setSuccess(false);
            return this;
        }

        public Builder success(boolean success) {
            entry.setSuccess(success);
            return this;
        }

        public Builder from(HttpServletRequest request) {
            entry.setIp(ClientInfo.ip(request));
            entry.setUserAgent(ClientInfo.userAgent(request));
            return this;
        }

        public Builder ip(String ip) {
            entry.setIp(ClientInfo.truncate(ip, 64));
            return this;
        }

        public void save() {
            try {
                writer.write(entry);
            } catch (RuntimeException e) {
                // Журнал не критичен для работы гейта — не даём ему уронить запрос.
                log.warn("Не удалось записать событие {} в журнал: {}",
                        entry.getType(), e.toString());
            }
            activityLog.info("{} user={} service={} ip={} ok={} {}",
                    entry.getType(),
                    entry.getUsername() == null ? "-" : entry.getUsername(),
                    entry.getServiceName() == null ? "-" : entry.getServiceName(),
                    entry.getIp() == null ? "-" : entry.getIp(),
                    entry.isSuccess(),
                    entry.getDetail() == null ? "" : entry.getDetail());
        }
    }
}
