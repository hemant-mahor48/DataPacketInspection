package com.datapacketinspection.controller;

import com.datapacketinspection.dto.LiveCaptureRequest;
import com.datapacketinspection.model.AnalysisSnapshot;
import com.datapacketinspection.model.CaptureInterfaceInfo;
import com.datapacketinspection.service.LiveCaptureService;
import com.datapacketinspection.service.PacketInspectionService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class PacketApiController {

    private final PacketInspectionService packetInspectionService;
    private final LiveCaptureService liveCaptureService;

    public PacketApiController(
            PacketInspectionService packetInspectionService,
            LiveCaptureService liveCaptureService) {
        this.packetInspectionService = packetInspectionService;
        this.liveCaptureService = liveCaptureService;
    }

    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public AnalysisSnapshot uploadPcap(@RequestParam("file") MultipartFile file)
            throws IOException, PcapNativeException, NotOpenException {
        return packetInspectionService.inspectUploadedPcap(file);
    }

    @GetMapping("/interfaces")
    public List<CaptureInterfaceInfo> interfaces() throws PcapNativeException {
        return liveCaptureService.listInterfaces();
    }

    @PostMapping("/live/start")
    public AnalysisSnapshot startLiveCapture(@Valid @RequestBody LiveCaptureRequest request)
            throws PcapNativeException, NotOpenException {
        liveCaptureService.startCapture(request.getInterfaceName());
        return liveCaptureService.currentSnapshot();
    }

    @PostMapping("/live/stop")
    public AnalysisSnapshot stopLiveCapture() {
        liveCaptureService.stopCapture();
        return liveCaptureService.currentSnapshot();
    }

    @GetMapping("/live/status")
    public AnalysisSnapshot liveStatus() {
        return liveCaptureService.currentSnapshot();
    }

    @ExceptionHandler({IllegalArgumentException.class, IOException.class, PcapNativeException.class, NotOpenException.class})
    public ResponseEntity<String> handleKnownFailures(Exception exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(exception.getMessage());
    }
}
