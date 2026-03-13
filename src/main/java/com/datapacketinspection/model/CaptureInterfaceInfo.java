package com.datapacketinspection.model;

import java.util.ArrayList;
import java.util.List;

public class CaptureInterfaceInfo {

    private String name;
    private String description;
    private List<String> addresses = new ArrayList<>();

    public CaptureInterfaceInfo() {
    }

    public CaptureInterfaceInfo(String name, String description, List<String> addresses) {
        this.name = name;
        this.description = description;
        this.addresses = addresses;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<String> addresses) {
        this.addresses = addresses;
    }
}
