package com.datapacketinspection.controller;

import com.datapacketinspection.dto.BrowserActivityRequest;
import com.datapacketinspection.entity.BrowserActivityEntity;
import com.datapacketinspection.service.BrowserActivityService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/browser-agent")
public class BrowserAgentController {

    private final BrowserActivityService browserActivityService;

    public BrowserAgentController(BrowserActivityService browserActivityService) {
        this.browserActivityService = browserActivityService;
    }

    @PostMapping("/activity")
    public BrowserActivityEntity recordActivity(@Valid @RequestBody BrowserActivityRequest request) {
        return browserActivityService.save(request);
    }
}
