package com.datapacketinspection.model;

public class TrafficTrendPoint {

    private String bucketLabel;
    private long totalPackets;
    private long allowedPackets;
    private long blockedPackets;
    private long reviewPackets;

    public String getBucketLabel() {
        return bucketLabel;
    }

    public void setBucketLabel(String bucketLabel) {
        this.bucketLabel = bucketLabel;
    }

    public long getTotalPackets() {
        return totalPackets;
    }

    public void setTotalPackets(long totalPackets) {
        this.totalPackets = totalPackets;
    }

    public long getAllowedPackets() {
        return allowedPackets;
    }

    public void setAllowedPackets(long allowedPackets) {
        this.allowedPackets = allowedPackets;
    }

    public long getBlockedPackets() {
        return blockedPackets;
    }

    public void setBlockedPackets(long blockedPackets) {
        this.blockedPackets = blockedPackets;
    }

    public long getReviewPackets() {
        return reviewPackets;
    }

    public void setReviewPackets(long reviewPackets) {
        this.reviewPackets = reviewPackets;
    }
}
