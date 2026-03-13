package com.datapacketinspection.config;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AsyncConfig {

    @Bean(destroyMethod = "shutdownNow")
    public ExecutorService liveCaptureExecutor() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "live-capture-executor");
            thread.setDaemon(true);
            return thread;
        });
    }
}
