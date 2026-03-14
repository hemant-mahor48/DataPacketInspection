package com.datapacketinspection.repository;

import com.datapacketinspection.entity.PacketEventEntity;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface PacketEventRepository extends JpaRepository<PacketEventEntity, Long>, JpaSpecificationExecutor<PacketEventEntity> {
    List<PacketEventEntity> findTop500ByOrderByTimestampDesc();
    List<PacketEventEntity> findByTimestampAfterOrderByTimestampAsc(Instant timestamp);
}
