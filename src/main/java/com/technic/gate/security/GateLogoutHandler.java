package com.technic.gate.security;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.service.ActivityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

/** Пишет в журнал факт выхода. Сессию чистит стандартный обработчик Spring Security. */
@Component
public class GateLogoutHandler implements LogoutHandler {

    private final ActivityService activityService;

    public GateLogoutHandler(ActivityService activityService) {
        this.activityService = activityService;
    }

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        if (authentication == null) {
            return;
        }
        Long userId = (authentication.getPrincipal() instanceof GateUserDetails details)
                ? details.getId() : null;
        activityService.event(ActivityType.LOGOUT)
                .user(authentication.getName(), userId)
                .from(request)
                .save();
    }
}
