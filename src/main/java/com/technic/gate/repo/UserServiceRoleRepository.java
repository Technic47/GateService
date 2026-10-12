package com.technic.gate.repo;

import com.technic.gate.domain.UserServiceRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface UserServiceRoleRepository extends JpaRepository<UserServiceRole, UserServiceRole.Key> {

    @Query("select r from UserServiceRole r where r.id.userId = :userId")
    List<UserServiceRole> findByUserId(Long userId);

    /** Коды активных ролей пользователя в приложении — для claim {@code roles}, по алфавиту. */
    @Query("""
            select a.code from UserServiceRole r, AppRole a
            where a.id = r.id.roleId and r.id.userId = :userId and r.id.serviceId = :serviceId
              and a.archivedAt is null
            order by a.code""")
    List<String> findActiveCodes(Long userId, Long serviceId);

    /** Сколько раз роль выдана (архивировать можно только невыданную). */
    @Query("select count(r) from UserServiceRole r where r.id.roleId = :roleId")
    long countByRoleId(Long roleId);

    @Modifying
    @Query("delete from UserServiceRole r where r.id.userId = :userId")
    void deleteByUserId(Long userId);
}
