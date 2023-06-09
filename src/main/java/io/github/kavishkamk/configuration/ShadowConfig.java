package io.github.kavishkamk.configuration;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "iot.device")
public interface ShadowConfig {

    String deviceRef();
    String deviceShadow();

}
