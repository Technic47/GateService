package com.technic.gate.repo;

import com.technic.gate.domain.ProtectedService;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProtectedServiceRepository extends JpaRepository<ProtectedService, Long> {

    Optional<ProtectedService> findByNameIgnoreCase(String name);

    boolean existsByNameIgnoreCase(String name);

    List<ProtectedService> findAllByOrderBySortOrderAscDisplayNameAsc();

    List<ProtectedService> findByEnabledTrueOrderBySortOrderAscDisplayNameAsc();
}
