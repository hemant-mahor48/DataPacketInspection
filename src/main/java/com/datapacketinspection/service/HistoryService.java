package com.datapacketinspection.service;

import com.datapacketinspection.entity.BrowserActivityEntity;
import com.datapacketinspection.entity.CaptureSessionEntity;
import com.datapacketinspection.entity.PacketEventEntity;
import com.datapacketinspection.model.AnalysisSnapshot;
import com.datapacketinspection.model.CaptureSessionType;
import com.datapacketinspection.model.PacketRecord;
import com.datapacketinspection.model.TrafficDecision;
import com.datapacketinspection.model.TrafficTrendPoint;
import com.datapacketinspection.repository.BrowserActivityRepository;
import com.datapacketinspection.repository.CaptureSessionRepository;
import com.datapacketinspection.repository.PacketEventRepository;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class HistoryService {

    private final CaptureSessionRepository captureSessionRepository;
    private final PacketEventRepository packetEventRepository;
    private final BrowserActivityRepository browserActivityRepository;

    public HistoryService(
            CaptureSessionRepository captureSessionRepository,
            PacketEventRepository packetEventRepository,
            BrowserActivityRepository browserActivityRepository) {
        this.captureSessionRepository = captureSessionRepository;
        this.packetEventRepository = packetEventRepository;
        this.browserActivityRepository = browserActivityRepository;
    }

    public CaptureSessionEntity saveSnapshot(
            CaptureSessionType sessionType,
            AnalysisSnapshot snapshot,
            String fileName,
            String interfaceName,
            Instant startedAt,
            Instant endedAt) {
        CaptureSessionEntity session = new CaptureSessionEntity();
        session.setSessionType(sessionType);
        session.setSourceName(snapshot.getSourceName());
        session.setFileName(fileName);
        session.setInterfaceName(interfaceName);
        session.setStartedAt(startedAt == null ? snapshot.getGeneratedAt() : startedAt);
        session.setEndedAt(endedAt == null ? snapshot.getGeneratedAt() : endedAt);
        session.setPacketCount(snapshot.getStats() == null ? snapshot.getRecords().size() : snapshot.getStats().getTotalPackets());
        session.setAllowedCount(snapshot.getStats() == null ? 0 : snapshot.getStats().getAllowedPackets());
        session.setBlockedCount(snapshot.getStats() == null ? 0 : snapshot.getStats().getBlockedPackets());
        session.setReviewCount(snapshot.getStats() == null ? 0 : snapshot.getStats().getReviewPackets());
        session.setNotes(String.join("\n", snapshot.getNotes()));
        session.setCreatedBy(currentUsername());

        CaptureSessionEntity savedSession = captureSessionRepository.save(session);
        List<PacketEventEntity> packetEvents = snapshot.getRecords().stream()
                .map(record -> toEntity(savedSession, record))
                .toList();
        packetEventRepository.saveAll(packetEvents);
        return savedSession;
    }

    public List<CaptureSessionEntity> recentSessions() {
        return captureSessionRepository.findTop20ByOrderByStartedAtDesc();
    }

    public List<PacketRecord> filterRecords(
            String ip,
            String protocol,
            String decision,
            String host,
            String service,
            int limit) {
        Specification<PacketEventEntity> specification = (root, query, builder) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (ip != null && !ip.isBlank()) {
                String pattern = "%" + ip.toLowerCase(Locale.ROOT) + "%";
                predicates.add(builder.or(
                        builder.like(builder.lower(root.get("sourceIp")), pattern),
                        builder.like(builder.lower(root.get("destinationIp")), pattern)));
            }
            if (protocol != null && !protocol.isBlank()) {
                predicates.add(builder.equal(builder.upper(root.get("protocol")), protocol.toUpperCase(Locale.ROOT)));
            }
            if (decision != null && !decision.isBlank()) {
                predicates.add(builder.equal(root.get("decision"), TrafficDecision.valueOf(decision.toUpperCase(Locale.ROOT))));
            }
            if (host != null && !host.isBlank()) {
                predicates.add(builder.like(builder.lower(root.get("detectedHost")), "%" + host.toLowerCase(Locale.ROOT) + "%"));
            }
            if (service != null && !service.isBlank()) {
                predicates.add(builder.like(builder.lower(root.get("serviceName")), "%" + service.toLowerCase(Locale.ROOT) + "%"));
            }
            return builder.and(predicates.toArray(new Predicate[0]));
        };

        List<PacketEventEntity> entities = packetEventRepository.findAll(specification, Sort.by(Sort.Direction.DESC, "timestamp"));
        return entities.stream().limit(limit).map(this::toRecord).toList();
    }

    public List<TrafficTrendPoint> buildTrendPoints(int minutes) {
        Instant since = Instant.now().minus(minutes, ChronoUnit.MINUTES);
        List<PacketEventEntity> events = packetEventRepository.findByTimestampAfterOrderByTimestampAsc(since);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
        Map<Instant, TrafficTrendPoint> buckets = new LinkedHashMap<>();

        for (PacketEventEntity event : events) {
            Instant bucketInstant = event.getTimestamp() == null
                    ? since.truncatedTo(ChronoUnit.MINUTES)
                    : event.getTimestamp().truncatedTo(ChronoUnit.MINUTES);
            TrafficTrendPoint point = buckets.computeIfAbsent(bucketInstant, key -> {
                TrafficTrendPoint item = new TrafficTrendPoint();
                item.setBucketLabel(formatter.format(key));
                return item;
            });
            point.setTotalPackets(point.getTotalPackets() + 1);
            if (event.getDecision() == TrafficDecision.ALLOWED) {
                point.setAllowedPackets(point.getAllowedPackets() + 1);
            } else if (event.getDecision() == TrafficDecision.BLOCKED) {
                point.setBlockedPackets(point.getBlockedPackets() + 1);
            } else {
                point.setReviewPackets(point.getReviewPackets() + 1);
            }
        }

        return new ArrayList<>(buckets.values());
    }

    public List<BrowserActivityEntity> recentBrowserActivity() {
        return browserActivityRepository.findTop20ByOrderByOccurredAtDesc();
    }

    private PacketEventEntity toEntity(CaptureSessionEntity session, PacketRecord record) {
        PacketEventEntity entity = new PacketEventEntity();
        entity.setSession(session);
        entity.setTimestamp(record.getTimestamp());
        entity.setSourceIp(record.getSourceIp());
        entity.setDestinationIp(record.getDestinationIp());
        entity.setSourcePort(record.getSourcePort());
        entity.setDestinationPort(record.getDestinationPort());
        entity.setProtocol(record.getProtocol());
        entity.setApplicationHint(record.getApplicationHint());
        entity.setDetectedHost(record.getDetectedHost());
        entity.setHostSource(record.getHostSource());
        entity.setServiceName(record.getServiceName());
        entity.setPacketSize(record.getPacketSize());
        entity.setDecision(record.getDecision());
        entity.setReason(record.getReason());
        return entity;
    }

    private PacketRecord toRecord(PacketEventEntity entity) {
        PacketRecord record = new PacketRecord();
        record.setTimestamp(entity.getTimestamp());
        record.setSourceIp(entity.getSourceIp());
        record.setDestinationIp(entity.getDestinationIp());
        record.setSourcePort(entity.getSourcePort());
        record.setDestinationPort(entity.getDestinationPort());
        record.setProtocol(entity.getProtocol());
        record.setApplicationHint(entity.getApplicationHint());
        record.setDetectedHost(entity.getDetectedHost());
        record.setHostSource(entity.getHostSource());
        record.setServiceName(entity.getServiceName());
        record.setPacketSize(entity.getPacketSize() == null ? 0 : entity.getPacketSize());
        record.setDecision(entity.getDecision());
        record.setReason(entity.getReason());
        return record;
    }

    private String currentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return "system";
        }
        return authentication.getName();
    }
}
