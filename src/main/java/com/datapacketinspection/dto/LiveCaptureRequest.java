package com.datapacketinspection.dto;

import jakarta.validation.constraints.NotBlank;

public class LiveCaptureRequest {

    @NotBlank(message = "A network interface name is required.")
    private String interfaceName;

    public String getInterfaceName() {
        return interfaceName;
    }

    public void setInterfaceName(String interfaceName) {
        this.interfaceName = interfaceName;
    }
}
