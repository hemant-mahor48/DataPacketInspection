package com.datapacketinspection.repository;

import com.datapacketinspection.entity.FirewallEventEntity;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FirewallEventRepository extends JpaRepository<FirewallEventEntity, Long> {
    List<FirewallEventEntity> findTop200ByOrderByEventTimeDesc();
    List<FirewallEventEntity> findByEventTimeBetweenAndDestinationIpAndDestinationPortAndProtocolAndActionIgnoreCase(
            Instant start,
            Instant end,
            String destinationIp,
            Integer destinationPort,
            String protocol,
            String action);
}
