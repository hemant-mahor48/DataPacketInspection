package com.datapacketinspection.repository;

import com.datapacketinspection.entity.CaptureSessionEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CaptureSessionRepository extends JpaRepository<CaptureSessionEntity, Long> {
    List<CaptureSessionEntity> findTop20ByOrderByStartedAtDesc();
}
