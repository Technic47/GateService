package com.technic.gate.config;

import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateSettingsService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Чистка журнала активности по расписанию.
 *
 * Журнал пишется на каждый отказ и вход, а диск на VPS — 30 ГБ, так что расти бесконечно
 * ему нельзя. Срок хранения задаётся на странице настроек; ноль означает «хранить вечно».
 */
@Component
public class ActivityRetentionJob {

    private final ActivityService activityService;
    private final GateSettingsService settingsService;

    public ActivityRetentionJob(ActivityService activityService,
                                GateSettingsService settingsService) {
        this.activityService = activityService;
        this.settingsService = settingsService;
    }

    /** Каждый день в 03:30 — время выбрано вне пиков и вне окна ротации логов Nginx. */
    @Scheduled(cron = "0 30 3 * * *")
    public void purge() {
        activityService.purgeOlderThan(settingsService.get().activityRetentionDays());
    }
}
