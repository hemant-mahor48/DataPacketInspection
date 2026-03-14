package com.datapacketinspection.service;

import com.datapacketinspection.dto.BrowserActivityRequest;
import com.datapacketinspection.entity.BrowserActivityEntity;
import com.datapacketinspection.repository.BrowserActivityRepository;
import java.net.URI;
import java.time.Instant;
import java.util.Locale;
import org.springframework.stereotype.Service;

@Service
public class BrowserActivityService {

    private final BrowserActivityRepository browserActivityRepository;

    public BrowserActivityService(BrowserActivityRepository browserActivityRepository) {
        this.browserActivityRepository = browserActivityRepository;
    }

    public BrowserActivityEntity save(BrowserActivityRequest request) {
        BrowserActivityEntity entity = new BrowserActivityEntity();
        entity.setOccurredAt(Instant.now());
        entity.setBrowserName(request.getBrowserName());
        entity.setPageTitle(request.getPageTitle());
        entity.setPageUrl(request.getPageUrl());
        entity.setTabId(request.getTabId());
        entity.setWindowId(request.getWindowId());
        entity.setHostname(extractHostname(request.getPageUrl()));
        entity.setServiceName(inferServiceName(entity.getHostname()));
        return browserActivityRepository.save(entity);
    }

    private String extractHostname(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception exception) {
            return null;
        }
    }

    private String inferServiceName(String host) {
        if (host == null || host.isBlank()) {
            return "Browser Activity";
        }
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.contains("youtube") || normalized.contains("googlevideo") || normalized.contains("ytimg")) {
            return "YouTube";
        }
        if (normalized.contains("instagram")) {
            return "Instagram";
        }
        if (normalized.contains("facebook") || normalized.contains("fbcdn") || normalized.contains("meta")) {
            return "Facebook/Meta";
        }
        if (normalized.contains("github")) {
            return "GitHub";
        }
        if (normalized.contains("linkedin")) {
            return "LinkedIn";
        }
        if (normalized.contains("netflix")) {
            return "Netflix";
        }
        if (normalized.contains("google")) {
            return "Google";
        }
        String[] labels = normalized.split("\\.");
        return labels.length >= 2 ? labels[labels.length - 2] : normalized;
    }
}
