package com.technic.gate.repo;

import com.technic.gate.domain.ActivityLog;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ActivityLogRepository
        extends JpaRepository<ActivityLog, Long>, JpaSpecificationExecutor<ActivityLog> {

    List<ActivityLog> findTop20ByUsernameOrderByAtDesc(String username);

    /** Чистка журнала по сроку хранения. Возвращает число удалённых строк. */
    @Modifying
    @Query("delete from ActivityLog a where a.at < :before")
    int deleteOlderThan(@Param("before") Instant before);

    long countByAtAfter(Instant since);

    @Query("select count(a) from ActivityLog a where a.at > :since and a.success = false")
    long countFailuresSince(@Param("since") Instant since);
}
