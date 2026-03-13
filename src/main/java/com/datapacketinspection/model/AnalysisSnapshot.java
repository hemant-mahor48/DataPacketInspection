package com.datapacketinspection.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class AnalysisSnapshot {

    private String sourceName;
    private Instant generatedAt;
    private boolean liveRunning;
    private String selectedInterface;
    private PacketStats stats;
    private List<PacketRecord> records = new ArrayList<>();
    private List<String> notes = new ArrayList<>();

    public String getSourceName() {
        return sourceName;
    }

    public void setSourceName(String sourceName) {
        this.sourceName = sourceName;
    }

    public Instant getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(Instant generatedAt) {
        this.generatedAt = generatedAt;
    }

    public boolean isLiveRunning() {
        return liveRunning;
    }

    public void setLiveRunning(boolean liveRunning) {
        this.liveRunning = liveRunning;
    }

    public String getSelectedInterface() {
        return selectedInterface;
    }

    public void setSelectedInterface(String selectedInterface) {
        this.selectedInterface = selectedInterface;
    }

    public PacketStats getStats() {
        return stats;
    }

    public void setStats(PacketStats stats) {
        this.stats = stats;
    }

    public List<PacketRecord> getRecords() {
        return records;
    }

    public void setRecords(List<PacketRecord> records) {
        this.records = records;
    }

    public List<String> getNotes() {
        return notes;
    }

    public void setNotes(List<String> notes) {
        this.notes = notes;
    }
}
