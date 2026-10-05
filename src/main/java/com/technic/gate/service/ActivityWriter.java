package com.technic.gate.service;

import com.technic.gate.domain.ActivityLog;
import com.technic.gate.repo.ActivityLogRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Вставка одной записи журнала в собственной транзакции.
 *
 * Отдельный бин, а не метод ActivityService: REQUIRES_NEW работает только через прокси,
 * а вызов собственного метода изнутри того же бина прокси минует. Смысл отдельной
 * транзакции в том, чтобы упавшая запись журнала не пометила транзакцию вызывающего
 * кода как rollback-only и не откатила, скажем, саму регистрацию пользователя.
 */
@Component
public class ActivityWriter {

    private final ActivityLogRepository repository;

    public ActivityWriter(ActivityLogRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void write(ActivityLog entry) {
        repository.save(entry);
    }
}
