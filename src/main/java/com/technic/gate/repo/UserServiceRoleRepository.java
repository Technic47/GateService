package com.technic.gate.repo;

import com.technic.gate.domain.UserServiceRole;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserServiceRoleRepository extends JpaRepository<UserServiceRole, UserServiceRole.Key> {

    @Query("select r from UserServiceRole r where r.id.userId = :userId")
    List<UserServiceRole> findByUserId(Long userId);

    @Modifying
    @Query("delete from UserServiceRole r where r.id.userId = :userId")
    void deleteByUserId(Long userId);
}
