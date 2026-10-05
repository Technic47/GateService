package com.technic.gate.web;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import org.springframework.stereotype.Component;

/**
 * Форматирование дат для шаблонов: ${@fmt.dateTime(...)}.
 *
 * Не через #temporals: Instant не привязан к зоне, и формат с датой на нём падает
 * с UnsupportedTemporalTypeException. Здесь зона применяется явно.
 */
@Component("fmt")
public class Formatter {

    private static final DateTimeFormatter DATE_TIME =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm");
    private static final DateTimeFormatter DATE_TIME_SECONDS =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");

    private final ZoneId zone = ZoneId.systemDefault();

    public String dateTime(Instant instant) {
        return instant == null ? "—" : DATE_TIME.format(instant.atZone(zone));
    }

    public String precise(Instant instant) {
        return instant == null ? "—" : DATE_TIME_SECONDS.format(instant.atZone(zone));
    }

    /** «5 мин назад» — для колонки последнего входа читается быстрее абсолютной даты. */
    public String ago(Instant instant) {
        if (instant == null) {
            return "никогда";
        }
        Duration d = Duration.between(instant, Instant.now());
        if (d.isNegative()) {
            return dateTime(instant);
        }
        long minutes = d.toMinutes();
        if (minutes < 1) {
            return "только что";
        }
        if (minutes < 60) {
            return minutes + " мин назад";
        }
        long hours = d.toHours();
        if (hours < 24) {
            return hours + " ч назад";
        }
        long days = d.toDays();
        if (days < 30) {
            return days + " дн назад";
        }
        return dateTime(instant);
    }
}
