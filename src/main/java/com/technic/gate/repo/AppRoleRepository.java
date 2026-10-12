package com.technic.gate.repo;

import com.technic.gate.domain.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

    /** Все роли для страницы ролей: глобальные первыми, дальше по приложению, порядку и коду. */
    @Query("select r from AppRole r order by case when r.serviceId is null then 0 else 1 end, r.serviceId, r.sortOrder, r.code")
    List<AppRole> findAllForAdmin();

    /** Роли, которые можно выдать в приложении: глобальные и его собственные, не в архиве. */
    @Query("""
            select r from AppRole r
            where r.archivedAt is null and (r.serviceId is null or r.serviceId = :serviceId)
            order by r.sortOrder, r.code""")
    List<AppRole> findAssignable(Long serviceId);

    @Query("select count(r) > 0 from AppRole r where r.code = :code and r.serviceId is null")
    boolean existsGlobal(String code);

    /** Есть ли другая роль (любой принадлежности) с этим кодом — для переноса роли в глобальные. */
    @Query("select count(r) > 0 from AppRole r where r.code = :code and r.id <> :id")
    boolean existsOtherWithCode(String code, Long id);

    @Query("select count(r) > 0 from AppRole r where r.code = :code and r.serviceId is not null")
    boolean existsInAnyService(String code);

    @Query("select count(r) > 0 from AppRole r where r.code = :code and r.serviceId = :serviceId")
    boolean existsInService(String code, Long serviceId);

    @Query(value = "select version from role_catalog_version where id = 1", nativeQuery = true)
    long catalogVersion();

    @Modifying
    @Query(value = "update role_catalog_version set version = version + 1 where id = 1", nativeQuery = true)
    void bumpCatalogVersion();
}
