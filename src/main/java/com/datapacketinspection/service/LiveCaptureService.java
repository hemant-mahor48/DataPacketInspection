package com.datapacketinspection.service;

import com.datapacketinspection.model.AnalysisSnapshot;
import com.datapacketinspection.model.CaptureInterfaceInfo;
import com.datapacketinspection.model.PacketRecord;
import com.datapacketinspection.model.TrafficDecision;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.springframework.stereotype.Service;

@Service
public class LiveCaptureService {

    private static final int MAX_RECORDS = 250;

    private final PacketInspectionService packetInspectionService;
    private final ExecutorService liveCaptureExecutor;

    private final Object monitor = new Object();
    private final Deque<PacketRecord> recentRecords = new ArrayDeque<>();
    private volatile boolean running;
    private volatile String activeInterfaceName;
    private volatile Future<?> captureTask;
    private volatile PcapHandle liveHandle;

    public LiveCaptureService(PacketInspectionService packetInspectionService, ExecutorService liveCaptureExecutor) {
        this.packetInspectionService = packetInspectionService;
        this.liveCaptureExecutor = liveCaptureExecutor;
    }

    public List<CaptureInterfaceInfo> listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces == null) {
            return List.of();
        }

        return interfaces.stream()
                .map(device -> new CaptureInterfaceInfo(
                        device.getName(),
                        device.getDescription(),
                        device.getAddresses().stream()
                                .map(address -> address.getAddress() == null ? "Unassigned" : address.getAddress().getHostAddress())
                                .collect(Collectors.toList())))
                .toList();
    }

    public void startCapture(String interfaceName) throws PcapNativeException, NotOpenException {
        synchronized (monitor) {
            if (running) {
                stopCapture();
            }

            PcapNetworkInterface networkInterface = Pcaps.getDevByName(interfaceName);
            if (networkInterface == null) {
                throw new IllegalArgumentException("Selected interface was not found: " + interfaceName);
            }

            recentRecords.clear();
            activeInterfaceName = interfaceName;
            liveHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            liveHandle.setFilter("ip or ip6", BpfCompileMode.OPTIMIZE);
            running = true;
            captureTask = liveCaptureExecutor.submit(() -> consumePackets(interfaceName));
        }
    }

    public void stopCapture() {
        synchronized (monitor) {
            running = false;
            if (liveHandle != null && liveHandle.isOpen()) {
                liveHandle.close();
            }
            liveHandle = null;
            if (captureTask != null) {
                captureTask.cancel(true);
                captureTask = null;
            }
        }
    }

    public AnalysisSnapshot currentSnapshot() {
        List<PacketRecord> snapshotRecords;
        synchronized (monitor) {
            snapshotRecords = new ArrayList<>(recentRecords);
        }

        List<String> notes = new ArrayList<>();
        notes.add("Live capture requires Npcap or WinPcap-compatible drivers and may need Administrator privileges on Windows.");
        notes.add("The dashboard keeps only the latest " + MAX_RECORDS + " packets in memory to stay responsive.");
        if (running) {
            notes.add("Capture is actively listening on interface: " + activeInterfaceName + ".");
        }

        return packetInspectionService.buildSnapshot(
                running ? "Live Traffic" : "Live Traffic (Stopped)",
                snapshotRecords,
                running,
                activeInterfaceName,
                notes
        );
    }

    private void consumePackets(String interfaceName) {
        while (running && liveHandle != null && liveHandle.isOpen()) {
            try {
                PacketRecord record = packetInspectionService.parsePacket(
                        liveHandle.getNextPacketEx(),
                        liveHandle.getTimestamp().toInstant()
                );
                synchronized (monitor) {
                    recentRecords.addFirst(record);
                    while (recentRecords.size() > MAX_RECORDS) {
                        recentRecords.removeLast();
                    }
                }
            } catch (TimeoutException exception) {
                // Expected for live capture polling windows.
            } catch (Exception exception) {
                synchronized (monitor) {
                    recentRecords.addFirst(errorRecord(interfaceName, exception.getMessage()));
                    while (recentRecords.size() > MAX_RECORDS) {
                        recentRecords.removeLast();
                    }
                }
                break;
            }
        }

        synchronized (monitor) {
            running = false;
            if (liveHandle != null && liveHandle.isOpen()) {
                liveHandle.close();
            }
            liveHandle = null;
        }
    }

    private PacketRecord errorRecord(String interfaceName, String message) {
        PacketRecord record = new PacketRecord();
        record.setTimestamp(Instant.now());
        record.setSourceIp(interfaceName);
        record.setDestinationIp("Capture Engine");
        record.setProtocol("SYSTEM");
        record.setApplicationHint("Live Capture");
        record.setPacketSize(0);
        record.setReason(message == null ? "Live capture stopped unexpectedly." : message);
        record.setDecision(TrafficDecision.REVIEW);
        return record;
    }
}
