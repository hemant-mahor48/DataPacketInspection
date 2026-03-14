package com.datapacketinspection.controller;

import com.datapacketinspection.entity.BrowserActivityEntity;
import com.datapacketinspection.entity.CaptureSessionEntity;
import com.datapacketinspection.entity.FirewallEventEntity;
import com.datapacketinspection.model.PacketRecord;
import com.datapacketinspection.model.TrafficTrendPoint;
import com.datapacketinspection.service.FirewallLogService;
import com.datapacketinspection.service.HistoryService;
import java.io.IOException;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/history")
public class HistoryApiController {

    private final HistoryService historyService;
    private final FirewallLogService firewallLogService;

    public HistoryApiController(HistoryService historyService, FirewallLogService firewallLogService) {
        this.historyService = historyService;
        this.firewallLogService = firewallLogService;
    }

    @GetMapping("/sessions")
    public List<CaptureSessionEntity> recentSessions() {
        return historyService.recentSessions();
    }

    @GetMapping("/records")
    public List<PacketRecord> filterRecords(
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String protocol,
            @RequestParam(required = false) String decision,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String service,
            @RequestParam(defaultValue = "200") int limit) {
        return historyService.filterRecords(ip, protocol, decision, host, service, Math.min(limit, 500));
    }

    @GetMapping("/trends")
    public List<TrafficTrendPoint> trendPoints(@RequestParam(defaultValue = "180") int minutes) {
        return historyService.buildTrendPoints(Math.min(minutes, 1440));
    }

    @GetMapping("/browser-activity")
    public List<BrowserActivityEntity> browserActivity() {
        return historyService.recentBrowserActivity();
    }

    @GetMapping("/firewall-events")
    public List<FirewallEventEntity> firewallEvents() {
        return firewallLogService.recentEvents();
    }

    @PostMapping("/firewall/upload")
    public String uploadFirewallLog(@RequestParam("file") MultipartFile file) throws IOException {
        int imported = firewallLogService.importFirewallLog(file);
        return "Imported " + imported + " firewall log entries.";
    }
}
