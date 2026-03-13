package com.datapacketinspection.model;

public class PacketStats {

    private int totalPackets;
    private int allowedPackets;
    private int blockedPackets;
    private int reviewPackets;
    private int tcpPackets;
    private int udpPackets;
    private int icmpPackets;
    private int dnsPackets;
    private int httpPackets;
    private int httpsPackets;

    public int getTotalPackets() {
        return totalPackets;
    }

    public void setTotalPackets(int totalPackets) {
        this.totalPackets = totalPackets;
    }

    public int getAllowedPackets() {
        return allowedPackets;
    }

    public void setAllowedPackets(int allowedPackets) {
        this.allowedPackets = allowedPackets;
    }

    public int getBlockedPackets() {
        return blockedPackets;
    }

    public void setBlockedPackets(int blockedPackets) {
        this.blockedPackets = blockedPackets;
    }

    public int getReviewPackets() {
        return reviewPackets;
    }

    public void setReviewPackets(int reviewPackets) {
        this.reviewPackets = reviewPackets;
    }

    public int getTcpPackets() {
        return tcpPackets;
    }

    public void setTcpPackets(int tcpPackets) {
        this.tcpPackets = tcpPackets;
    }

    public int getUdpPackets() {
        return udpPackets;
    }

    public void setUdpPackets(int udpPackets) {
        this.udpPackets = udpPackets;
    }

    public int getIcmpPackets() {
        return icmpPackets;
    }

    public void setIcmpPackets(int icmpPackets) {
        this.icmpPackets = icmpPackets;
    }

    public int getDnsPackets() {
        return dnsPackets;
    }

    public void setDnsPackets(int dnsPackets) {
        this.dnsPackets = dnsPackets;
    }

    public int getHttpPackets() {
        return httpPackets;
    }

    public void setHttpPackets(int httpPackets) {
        this.httpPackets = httpPackets;
    }

    public int getHttpsPackets() {
        return httpsPackets;
    }

    public void setHttpsPackets(int httpsPackets) {
        this.httpsPackets = httpsPackets;
    }
}
