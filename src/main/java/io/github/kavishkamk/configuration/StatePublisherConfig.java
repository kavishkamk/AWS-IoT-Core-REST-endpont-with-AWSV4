package io.github.kavishkamk.configuration;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix="aws.iot")
public interface StatePublisherConfig {

    String endpoint();
    String region();
    String awsAccessKeyId();
    String awsSecretKey();
}
