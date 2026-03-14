package com.datapacketinspection.service;

import com.datapacketinspection.entity.FirewallEventEntity;
import com.datapacketinspection.repository.FirewallEventRepository;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class FirewallLogService {

    private static final DateTimeFormatter WINDOWS_FIREWALL_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final FirewallEventRepository firewallEventRepository;

    public FirewallLogService(FirewallEventRepository firewallEventRepository) {
        this.firewallEventRepository = firewallEventRepository;
    }

    public int importFirewallLog(MultipartFile file) throws IOException {
        List<FirewallEventEntity> events = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                FirewallEventEntity event = parseLine(line);
                if (event != null) {
                    events.add(event);
                }
            }
        }
        firewallEventRepository.saveAll(events);
        return events.size();
    }

    public Optional<FirewallEventEntity> findBlockingMatch(Instant timestamp, String destinationIp, Integer destinationPort, String protocol) {
        if (timestamp == null || destinationIp == null || destinationPort == null || protocol == null) {
            return Optional.empty();
        }
        List<FirewallEventEntity> matches = firewallEventRepository
                .findByEventTimeBetweenAndDestinationIpAndDestinationPortAndProtocolAndActionIgnoreCase(
                        timestamp.minusSeconds(120),
                        timestamp.plusSeconds(120),
                        destinationIp,
                        destinationPort,
                        protocol.toUpperCase(Locale.ROOT),
                        "DROP");
        return matches.stream().findFirst();
    }

    public List<FirewallEventEntity> recentEvents() {
        return firewallEventRepository.findTop200ByOrderByEventTimeDesc();
    }

    private FirewallEventEntity parseLine(String line) {
        if (line == null || line.isBlank() || line.startsWith("#")) {
            return null;
        }
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 8) {
            return null;
        }

        try {
            FirewallEventEntity entity = new FirewallEventEntity();
            entity.setEventTime(LocalDateTime.parse(parts[0] + " " + parts[1], WINDOWS_FIREWALL_TIME)
                    .atZone(ZoneId.systemDefault())
                    .toInstant());
            entity.setAction(parts[2]);
            entity.setProtocol(parts[3].toUpperCase(Locale.ROOT));
            entity.setSourceIp(parts[4]);
            entity.setDestinationIp(parts[5]);
            entity.setSourcePort(parsePort(parts[6]));
            entity.setDestinationPort(parsePort(parts[7]));
            entity.setRawLine(line);
            return entity;
        } catch (Exception exception) {
            return null;
        }
    }

    private Integer parsePort(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            return null;
        }
    }
}
