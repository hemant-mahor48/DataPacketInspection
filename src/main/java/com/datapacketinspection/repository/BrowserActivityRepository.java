package com.datapacketinspection.repository;

import com.datapacketinspection.entity.BrowserActivityEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BrowserActivityRepository extends JpaRepository<BrowserActivityEntity, Long> {
    List<BrowserActivityEntity> findTop20ByOrderByOccurredAtDesc();
}
