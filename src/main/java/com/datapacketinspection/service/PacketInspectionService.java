package com.datapacketinspection.service;

import com.datapacketinspection.entity.FirewallEventEntity;
import com.datapacketinspection.model.AnalysisSnapshot;
import com.datapacketinspection.model.CaptureSessionType;
import com.datapacketinspection.model.PacketRecord;
import com.datapacketinspection.model.PacketStats;
import com.datapacketinspection.model.TrafficDecision;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class PacketInspectionService {

    private static final Set<Integer> POLICY_BLOCKED_PORTS = Set.of(23, 69, 135, 137, 138, 139, 445, 3389);
    private static final int MAX_RECORDS = 300;
    private static final Pattern HTTP_HOST_PATTERN = Pattern.compile("(?im)^Host:\\s*([^\\r\\n:]+)");
    private static final Set<String> HTTP_METHOD_PREFIXES = Set.of(
            "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "
    );

    private final HistoryService historyService;
    private final FirewallLogService firewallLogService;

    public PacketInspectionService(HistoryService historyService, FirewallLogService firewallLogService) {
        this.historyService = historyService;
        this.firewallLogService = firewallLogService;
    }

    public AnalysisSnapshot inspectUploadedPcap(MultipartFile file)
            throws IOException, PcapNativeException, NotOpenException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Please upload a non-empty PCAP or PCAPNG file.");
        }

        String filename = file.getOriginalFilename() == null ? "uploaded-capture.pcap" : file.getOriginalFilename();
        String normalized = filename.toLowerCase(Locale.ROOT);
        if (!normalized.endsWith(".pcap") && !normalized.endsWith(".pcapng")) {
            throw new IllegalArgumentException("Only .pcap and .pcapng files are supported.");
        }

        Instant startedAt = Instant.now();
        Path tempFile = Files.createTempFile("packet-upload-", "-" + filename);
        file.transferTo(tempFile);

        List<PacketRecord> records = new ArrayList<>();
        try (PcapHandle handle = Pcaps.openOffline(tempFile.toString())) {
            while (records.size() < MAX_RECORDS) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    records.add(parsePacket(packet, handle.getTimestamp().toInstant()));
                } catch (EOFException exception) {
                    break;
                } catch (java.util.concurrent.TimeoutException exception) {
                    // Offline reads do not usually time out, but skipping keeps parsing resilient.
                }
            }
        } finally {
            Files.deleteIfExists(tempFile);
        }

        AnalysisSnapshot snapshot = buildSnapshot(filename, records, false, null,
                List.of(
                        "Blocked traffic is inferred from packet evidence such as TCP resets, ICMP unreachable responses, policy-denied ports, and imported firewall DROP logs.",
                        "Detected hostnames come from DNS queries, HTTP Host headers, and TLS SNI when those values are visible in the capture.",
                        "Up to " + MAX_RECORDS + " packets are loaded into the dashboard table for readability."
                ));
        historyService.saveSnapshot(CaptureSessionType.UPLOAD, snapshot, filename, null, startedAt, Instant.now());
        return snapshot;
    }

    public PacketRecord parsePacket(Packet packet, Instant timestamp) {
        PacketRecord record = new PacketRecord();
        record.setTimestamp(timestamp);
        record.setPacketSize(packet.length());
        record.setProtocol("UNKNOWN");
        record.setApplicationHint("Unknown");
        record.setServiceName("Unknown Service");
        record.setDecision(TrafficDecision.REVIEW);
        record.setReason("Packet requires manual review.");

        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket == null) {
            record.setReason("Non-IP packet captured.");
            return record;
        }

        record.setSourceIp(readHost(ipPacket.getHeader().getSrcAddr()));
        record.setDestinationIp(readHost(ipPacket.getHeader().getDstAddr()));
        record.setProtocol(ipPacket.getHeader().getProtocol().name());

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            record.setSourcePort(srcPort);
            record.setDestinationPort(dstPort);
            record.setApplicationHint(inferApplication(srcPort, dstPort, true));
            populateDetectedHost(record, extractHttpHost(tcpPacket), "HTTP Host");
            if (record.getDetectedHost() == null) {
                populateDetectedHost(record, extractTlsSni(tcpPacket), "TLS SNI");
            }

            if (Boolean.TRUE.equals(tcpPacket.getHeader().getRst())) {
                record.setDecision(TrafficDecision.BLOCKED);
                record.setReason("TCP reset observed, which often indicates rejected or interrupted traffic.");
            } else if (POLICY_BLOCKED_PORTS.contains(dstPort)) {
                record.setDecision(TrafficDecision.BLOCKED);
                record.setReason("Destination port matches the local policy deny list.");
            } else if (Boolean.TRUE.equals(tcpPacket.getHeader().getSyn()) && !Boolean.TRUE.equals(tcpPacket.getHeader().getAck())) {
                record.setDecision(TrafficDecision.ALLOWED);
                record.setReason("Outbound connection attempt observed.");
            } else {
                record.setDecision(TrafficDecision.ALLOWED);
                record.setReason("TCP traffic looks permitted based on the observed handshake state.");
            }

            applyFirewallCorrelation(record);
            finalizeServiceName(record);
            return record;
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
            record.setSourcePort(srcPort);
            record.setDestinationPort(dstPort);
            record.setApplicationHint(inferApplication(srcPort, dstPort, false));
            if (srcPort == 53 || dstPort == 53) {
                populateDetectedHost(record, extractDnsQuestionName(udpPacket), "DNS Question");
            }

            if (POLICY_BLOCKED_PORTS.contains(dstPort)) {
                record.setDecision(TrafficDecision.BLOCKED);
                record.setReason("UDP destination port matches the local policy deny list.");
            } else {
                record.setDecision(TrafficDecision.ALLOWED);
                record.setReason("UDP traffic was captured without an explicit deny signal.");
            }

            applyFirewallCorrelation(record);
            finalizeServiceName(record);
            return record;
        }

        IcmpV4CommonPacket icmpV4Packet = packet.get(IcmpV4CommonPacket.class);
        if (icmpV4Packet != null) {
            record.setProtocol("ICMPv4");
            record.setApplicationHint("ICMP");
            record.setServiceName("Network Control");
            if (icmpV4Packet.getHeader().getType().name().toLowerCase(Locale.ROOT).contains("unreachable")) {
                record.setDecision(TrafficDecision.BLOCKED);
                record.setReason("ICMP destination unreachable response captured.");
            } else {
                record.setDecision(TrafficDecision.ALLOWED);
                record.setReason("ICMP traffic captured for diagnostics or reachability.");
            }
            return record;
        }

        IcmpV6CommonPacket icmpV6Packet = packet.get(IcmpV6CommonPacket.class);
        if (icmpV6Packet != null) {
            record.setProtocol("ICMPv6");
            record.setApplicationHint("ICMP");
            record.setServiceName("Network Control");
            if (icmpV6Packet.getHeader().getType().name().toLowerCase(Locale.ROOT).contains("unreachable")) {
                record.setDecision(TrafficDecision.BLOCKED);
                record.setReason("ICMPv6 unreachable response captured.");
            } else {
                record.setDecision(TrafficDecision.ALLOWED);
                record.setReason("ICMPv6 traffic captured for diagnostics or neighbor discovery.");
            }
        }

        return record;
    }

    public AnalysisSnapshot buildSnapshot(
            String sourceName,
            List<PacketRecord> records,
            boolean liveRunning,
            String selectedInterface,
            List<String> notes) {
        List<PacketRecord> orderedRecords = records.stream()
                .sorted(Comparator.comparing(PacketRecord::getTimestamp, Comparator.nullsLast(Comparator.naturalOrder())).reversed())
                .toList();

        AnalysisSnapshot snapshot = new AnalysisSnapshot();
        snapshot.setSourceName(sourceName);
        snapshot.setGeneratedAt(Instant.now());
        snapshot.setLiveRunning(liveRunning);
        snapshot.setSelectedInterface(selectedInterface);
        snapshot.setRecords(orderedRecords);
        snapshot.setStats(summarize(orderedRecords));
        snapshot.setNotes(notes);
        return snapshot;
    }

    private PacketStats summarize(List<PacketRecord> records) {
        PacketStats stats = new PacketStats();
        stats.setTotalPackets(records.size());

        for (PacketRecord record : records) {
            if (record.getDecision() == TrafficDecision.ALLOWED) {
                stats.setAllowedPackets(stats.getAllowedPackets() + 1);
            } else if (record.getDecision() == TrafficDecision.BLOCKED) {
                stats.setBlockedPackets(stats.getBlockedPackets() + 1);
            } else {
                stats.setReviewPackets(stats.getReviewPackets() + 1);
            }

            String protocol = record.getProtocol() == null ? "" : record.getProtocol().toUpperCase(Locale.ROOT);
            String application = record.getApplicationHint() == null ? "" : record.getApplicationHint().toUpperCase(Locale.ROOT);

            if (protocol.contains("TCP")) {
                stats.setTcpPackets(stats.getTcpPackets() + 1);
            }
            if (protocol.contains("UDP")) {
                stats.setUdpPackets(stats.getUdpPackets() + 1);
            }
            if (protocol.contains("ICMP")) {
                stats.setIcmpPackets(stats.getIcmpPackets() + 1);
            }
            if (application.contains("DNS")) {
                stats.setDnsPackets(stats.getDnsPackets() + 1);
            }
            if (application.contains("HTTP/WEB")) {
                stats.setHttpPackets(stats.getHttpPackets() + 1);
            }
            if (application.contains("HTTPS")) {
                stats.setHttpsPackets(stats.getHttpsPackets() + 1);
            }
        }

        return stats;
    }

    private void applyFirewallCorrelation(PacketRecord record) {
        Optional<FirewallEventEntity> match = firewallLogService.findBlockingMatch(
                record.getTimestamp(),
                record.getDestinationIp(),
                record.getDestinationPort(),
                record.getProtocol());
        match.ifPresent(event -> {
            record.setDecision(TrafficDecision.BLOCKED);
            record.setReason("Matched imported firewall DROP log for destination " + event.getDestinationIp() + ":" + event.getDestinationPort());
        });
    }

    private void populateDetectedHost(PacketRecord record, String host, String source) {
        if (host == null || host.isBlank()) {
            return;
        }

        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        record.setDetectedHost(normalizedHost);
        record.setHostSource(source);
    }

    private void finalizeServiceName(PacketRecord record) {
        record.setServiceName(inferServiceName(record.getDetectedHost(), record.getApplicationHint()));
    }

    private String readHost(InetAddress address) {
        return address == null ? "Unknown" : address.getHostAddress();
    }

    private String inferApplication(int srcPort, int dstPort, boolean tcp) {
        Set<Integer> ports = new HashSet<>(List.of(srcPort, dstPort));
        if (ports.contains(53)) {
            return "DNS";
        }
        if (ports.contains(80) || ports.contains(8080)) {
            return "HTTP/Web";
        }
        if (ports.contains(443)) {
            return tcp ? "HTTPS/TLS" : "QUIC/HTTPS";
        }
        if (ports.contains(123)) {
            return "NTP";
        }
        if (ports.contains(22)) {
            return "SSH";
        }
        if (ports.contains(25) || ports.contains(587)) {
            return "SMTP";
        }
        if (ports.contains(110) || ports.contains(995)) {
            return "POP3";
        }
        if (ports.contains(143) || ports.contains(993)) {
            return "IMAP";
        }
        if (ports.contains(3306)) {
            return "MySQL";
        }
        if (ports.contains(3389)) {
            return "RDP";
        }
        return tcp ? "TCP Service" : "UDP Service";
    }

    private String inferServiceName(String host, String applicationHint) {
        if (host != null && !host.isBlank()) {
            String normalized = host.toLowerCase(Locale.ROOT);
            if (normalized.contains("youtube") || normalized.contains("googlevideo.com") || normalized.contains("ytimg.com")) {
                return "YouTube";
            }
            if (normalized.contains("instagram")) {
                return "Instagram";
            }
            if (normalized.contains("facebook") || normalized.contains("fbcdn.net") || normalized.contains("meta.com")) {
                return "Facebook/Meta";
            }
            if (normalized.contains("whatsapp")) {
                return "WhatsApp";
            }
            if (normalized.contains("google") || normalized.contains("gstatic.com") || normalized.contains("googleapis.com")) {
                return "Google";
            }
            if (normalized.contains("netflix")) {
                return "Netflix";
            }
            if (normalized.contains("amazon") || normalized.contains("aws")) {
                return "Amazon/AWS";
            }
            if (normalized.contains("microsoft") || normalized.contains("live.com") || normalized.contains("office.com") || normalized.contains("windows.com")) {
                return "Microsoft";
            }
            if (normalized.contains("cloudflare")) {
                return "Cloudflare";
            }
            if (normalized.contains("spotify")) {
                return "Spotify";
            }
            if (normalized.contains("twitter") || normalized.contains("x.com") || normalized.contains("twimg.com")) {
                return "X/Twitter";
            }
            if (normalized.contains("linkedin")) {
                return "LinkedIn";
            }
            if (normalized.contains("github")) {
                return "GitHub";
            }
            return highestLevelServiceName(normalized);
        }

        if (applicationHint == null || applicationHint.isBlank()) {
            return "Unknown Service";
        }
        return applicationHint;
    }

    private String highestLevelServiceName(String host) {
        String[] labels = host.split("\\.");
        if (labels.length == 0) {
            return "Unknown Service";
        }
        String candidate = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
        if (candidate.isBlank()) {
            return "Unknown Service";
        }
        return candidate.substring(0, 1).toUpperCase(Locale.ROOT) + candidate.substring(1);
    }

    private String extractHttpHost(TcpPacket tcpPacket) {
        if (tcpPacket.getPayload() == null) {
            return null;
        }

        byte[] payload = tcpPacket.getPayload().getRawData();
        if (payload.length == 0) {
            return null;
        }

        String text = new String(payload, 0, Math.min(payload.length, 2048), StandardCharsets.US_ASCII);
        boolean looksLikeHttp = text.startsWith("HTTP/") || HTTP_METHOD_PREFIXES.stream().anyMatch(text::startsWith);
        if (!looksLikeHttp) {
            return null;
        }

        Matcher matcher = HTTP_HOST_PATTERN.matcher(text);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private String extractDnsQuestionName(UdpPacket udpPacket) {
        if (udpPacket.getPayload() == null) {
            return null;
        }

        byte[] payload = udpPacket.getPayload().getRawData();
        if (payload.length < 12) {
            return null;
        }

        int questionCount = readUnsignedShort(payload, 4);
        if (questionCount < 1) {
            return null;
        }

        int offset = 12;
        StringBuilder hostname = new StringBuilder();
        while (offset < payload.length) {
            int labelLength = payload[offset] & 0xFF;
            if (labelLength == 0) {
                return hostname.length() == 0 ? null : hostname.toString();
            }
            if ((labelLength & 0xC0) == 0xC0) {
                return hostname.length() == 0 ? null : hostname.toString();
            }
            offset++;
            if (offset + labelLength > payload.length) {
                return null;
            }
            if (hostname.length() > 0) {
                hostname.append('.');
            }
            hostname.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
            offset += labelLength;
        }

        return null;
    }

    private String extractTlsSni(TcpPacket tcpPacket) {
        if (tcpPacket.getPayload() == null) {
            return null;
        }

        byte[] payload = tcpPacket.getPayload().getRawData();
        if (payload.length < 5 || (payload[0] & 0xFF) != 22) {
            return null;
        }

        int recordOffset = 0;
        while (recordOffset + 5 <= payload.length) {
            int contentType = payload[recordOffset] & 0xFF;
            int recordLength = readUnsignedShort(payload, recordOffset + 3);
            int recordBodyStart = recordOffset + 5;
            int recordEnd = recordBodyStart + recordLength;
            if (recordEnd > payload.length) {
                return null;
            }
            if (contentType == 22) {
                String sni = parseTlsHandshakeForSni(payload, recordBodyStart, recordEnd);
                if (sni != null) {
                    return sni;
                }
            }
            recordOffset = recordEnd;
        }

        return null;
    }

    private String parseTlsHandshakeForSni(byte[] payload, int start, int end) {
        int offset = start;
        while (offset + 4 <= end) {
            int handshakeType = payload[offset] & 0xFF;
            int handshakeLength = readUnsignedMedium(payload, offset + 1);
            int handshakeBodyStart = offset + 4;
            int handshakeEnd = handshakeBodyStart + handshakeLength;
            if (handshakeEnd > end) {
                return null;
            }
            if (handshakeType == 1) {
                return parseClientHelloForSni(payload, handshakeBodyStart, handshakeEnd);
            }
            offset = handshakeEnd;
        }
        return null;
    }

    private String parseClientHelloForSni(byte[] payload, int start, int end) {
        int offset = start;
        if (offset + 34 > end) {
            return null;
        }

        offset += 2;
        offset += 32;

        if (offset + 1 > end) {
            return null;
        }
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > end) {
            return null;
        }

        int cipherSuiteLength = readUnsignedShort(payload, offset);
        offset += 2 + cipherSuiteLength;
        if (offset + 1 > end) {
            return null;
        }

        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > end) {
            return null;
        }

        int extensionsLength = readUnsignedShort(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(offset + extensionsLength, end);
        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUnsignedShort(payload, offset);
            int extensionLength = readUnsignedShort(payload, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd) {
                return null;
            }
            if (extensionType == 0) {
                return parseServerNameExtension(payload, offset, extensionLength);
            }
            offset += extensionLength;
        }

        return null;
    }

    private String parseServerNameExtension(byte[] payload, int start, int length) {
        if (length < 2 || start + length > payload.length) {
            return null;
        }

        int offset = start;
        int listLength = readUnsignedShort(payload, offset);
        offset += 2;
        int listEnd = Math.min(offset + listLength, start + length);
        while (offset + 3 <= listEnd) {
            int nameType = payload[offset] & 0xFF;
            int nameLength = readUnsignedShort(payload, offset + 1);
            offset += 3;
            if (offset + nameLength > listEnd) {
                return null;
            }
            if (nameType == 0) {
                return new String(payload, offset, nameLength, StandardCharsets.US_ASCII);
            }
            offset += nameLength;
        }
        return null;
    }

    private int readUnsignedShort(byte[] data, int offset) {
        if (offset + 1 >= data.length) {
            return 0;
        }
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private int readUnsignedMedium(byte[] data, int offset) {
        if (offset + 2 >= data.length) {
            return 0;
        }
        return ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
    }
}
