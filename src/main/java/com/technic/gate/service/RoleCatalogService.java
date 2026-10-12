package com.technic.gate.service;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.AppRole;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.repo.AppRoleRepository;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserServiceRoleRepository;
import io.github.technic47.gateauth.core.RoleCatalog;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Справочник ролей приложений (Gate Auth §4.4–4.5). Гейт — единственное место, где роли определяются;
 * приложения получают свой список ({@link #catalogFor}) и сами решают, что роль разрешает.
 *
 * Правила:
 * <ul>
 *   <li>код — строчная латиница ({@link RoleCatalog#CODE}), после создания не меняется;</li>
 *   <li>принадлежность меняется ({@link #changeScope}): роль сервиса → глобальная, если кода нет больше нигде;
 *       глобальная → роль сервиса, если она не выдана в других сервисах;</li>
 *   <li>в одном приложении код не повторяется: глобальный код не может совпасть с кодом роли какого-либо
 *       приложения и наоборот;</li>
 *   <li>вместо удаления — архив; архивировать можно только роль, которая ни у кого не выдана;</li>
 *   <li>любое изменение определения роли поднимает версию каталога (claim {@code rv}).</li>
 * </ul>
 */
@Service
public class RoleCatalogService {

    private final AppRoleRepository roles;
    private final UserServiceRoleRepository assignments;
    private final ProtectedServiceRepository services;
    private final ActivityService activityService;
    private final GateTokenService tokenService;
    private final Clock clock = Clock.systemUTC();

    public RoleCatalogService(AppRoleRepository roles, UserServiceRoleRepository assignments,
                              ProtectedServiceRepository services, ActivityService activityService,
                              GateTokenService tokenService) {
        this.roles = roles;
        this.assignments = assignments;
        this.services = services;
        this.activityService = activityService;
        this.tokenService = tokenService;
    }

    /** Строка страницы ролей: роль, её приложение (или {@code null} для глобальной) и сколько раз она выдана. */
    public record RoleRow(AppRole role, ProtectedService service, long assigned) {
    }

    @Transactional(readOnly = true)
    public List<RoleRow> allForAdmin() {
        Map<Long, ProtectedService> byId = services.findAll().stream()
                .collect(Collectors.toMap(ProtectedService::getId, Function.identity()));
        return roles.findAllForAdmin().stream()
                .map(r -> new RoleRow(r, r.isGlobal() ? null : byId.get(r.getServiceId()),
                        assignments.countByRoleId(r.getId())))
                .toList();
    }

    /** Роли, которые можно выдать в приложении: глобальные и его собственные, без архивных. */
    @Transactional(readOnly = true)
    public List<AppRole> assignable(Long serviceId) {
        return roles.findAssignable(serviceId);
    }

    @Transactional(readOnly = true)
    public AppRole require(Long id) {
        return roles.findById(id).orElseThrow(() -> new GateException("Роль не найдена"));
    }

    @Transactional(readOnly = true)
    public long version() {
        return roles.catalogVersion();
    }

    @Transactional
    public AppRole create(String code, String name, String description, Long serviceId, int sortOrder, String actor) {
        String c = code == null ? "" : code.strip();
        if (!RoleCatalog.CODE.matcher(c).matches()) {
            throw new GateException("Код роли: строчная латиница, цифры, дефис, подчёркивание, до 32 символов, "
                    + "с буквы (например editor)");
        }
        requireName(name);
        ProtectedService service = null;
        if (serviceId != null) {
            service = services.findById(serviceId).orElseThrow(() -> new GateException("Сервис не найден"));
            if (roles.existsInService(c, serviceId)) {
                throw new GateException("В сервисе " + service.getName() + " роль " + c + " уже есть");
            }
            if (roles.existsGlobal(c)) {
                throw new GateException("Есть глобальная роль " + c + ": она уже доступна во всех сервисах");
            }
        } else {
            if (roles.existsGlobal(c)) {
                throw new GateException("Глобальная роль " + c + " уже есть");
            }
            if (roles.existsInAnyService(c)) {
                throw new GateException("Роль " + c + " уже есть у одного из сервисов: глобальная с тем же кодом "
                        + "дала бы в нём два одинаковых кода");
            }
        }
        AppRole role = roles.save(new AppRole(c, name, description, serviceId, sortOrder, clock.instant()));
        changed(ActivityType.ROLE_CREATED, actor, service,
                "Создана роль " + c + (service == null ? " (глобальная)" : " для " + service.getName()));
        return role;
    }

    @Transactional
    public AppRole update(Long id, String name, String description, int sortOrder, String actor) {
        requireName(name);
        AppRole role = require(id);
        role.describe(name, description, sortOrder, clock.instant());
        changed(ActivityType.ROLE_UPDATED, actor, serviceOf(role), "Изменена роль " + role.getCode());
        return role;
    }

    /**
     * Меняет принадлежность роли. Код остаётся, выдачи сохраняются.
     *
     * @param serviceId новый сервис или {@code null} — сделать глобальной
     */
    @Transactional
    public AppRole changeScope(Long id, Long serviceId, String actor) {
        AppRole role = require(id);
        if (java.util.Objects.equals(role.getServiceId(), serviceId)) {
            return role;
        }
        ProtectedService target = null;
        if (serviceId == null) {
            if (roles.existsOtherWithCode(role.getCode(), id)) {
                throw new GateException("Роль " + role.getCode() + " есть ещё в другом сервисе: глобальная с тем же "
                        + "кодом дала бы там два одинаковых кода");
            }
        } else {
            target = services.findById(serviceId).orElseThrow(() -> new GateException("Сервис не найден"));
            if (roles.existsInService(role.getCode(), serviceId)) {
                throw new GateException("В сервисе " + target.getName() + " роль " + role.getCode() + " уже есть");
            }
            long elsewhere = assignments.countByRoleIdOutsideService(id, serviceId);
            if (elsewhere > 0) {
                throw new GateException("Роль " + role.getCode() + " выдана в других сервисах (" + elsewhere
                        + " раз): сначала снимите её там");
            }
        }
        ProtectedService before = serviceOf(role);
        role.moveTo(serviceId, clock.instant());
        changed(ActivityType.ROLE_UPDATED, actor, target != null ? target : before,
                "Роль " + role.getCode() + ": " + (before == null ? "глобальная" : before.getName()) + " → "
                        + (target == null ? "глобальная" : target.getName()));
        return role;
    }

    @Transactional
    public void setArchived(Long id, boolean archived, String actor) {
        AppRole role = require(id);
        if (archived) {
            long assigned = assignments.countByRoleId(id);
            if (assigned > 0) {
                throw new GateException("Роль " + role.getCode() + " выдана " + assigned
                        + " раз(а): сначала снимите её с пользователей");
            }
            role.archive(clock.instant());
        } else {
            role.restore(clock.instant());
        }
        changed(archived ? ActivityType.ROLE_ARCHIVED : ActivityType.ROLE_RESTORED, actor, serviceOf(role),
                (archived ? "В архив роль " : "Из архива роль ") + role.getCode());
    }

    /**
     * Подписанный каталог ролей приложения (§4.5) — тело ответа {@code /.well-known/gate/apps/{app}/roles}.
     *
     * @return пусто, если сервиса нет, он отключён или у гейта нет ключа подписи
     */
    @Transactional(readOnly = true)
    public Optional<String> catalogFor(String serviceName) {
        return services.findByNameIgnoreCase(serviceName)
                .filter(ProtectedService::isEnabled)
                .flatMap(service -> tokenService.signRoleCatalog(service.getName(), roles.catalogVersion(),
                        roles.findAssignable(service.getId()).stream()
                                .map(r -> new RoleCatalog.Role(r.getCode(), r.getName(), r.getDescription(),
                                        r.isGlobal()))
                                .toList()));
    }

    /** Версия каталога растёт, кеш выданных токенов сбрасывается (в них claim rv), событие — в журнал. */
    private void changed(ActivityType type, String actor, ProtectedService service, String detail) {
        roles.bumpCatalogVersion();
        tokenService.evictCache();
        var event = activityService.event(type).user(actor, null).detail(detail);
        if (service != null) {
            event.service(service.getName());
        }
        event.save();
    }

    private ProtectedService serviceOf(AppRole role) {
        return role.isGlobal() ? null : services.findById(role.getServiceId()).orElse(null);
    }

    private static void requireName(String name) {
        if (name == null || name.isBlank() || name.strip().length() > 100) {
            throw new GateException("Название роли обязательно, до 100 символов");
        }
    }
}
