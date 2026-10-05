package com.technic.gate.repo;

import com.technic.gate.domain.GateSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GateSettingRepository extends JpaRepository<GateSetting, String> {
}
