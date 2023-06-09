package io.github.kavishkamk.state;
import io.github.kavishkamk.configuration.ShadowConfig;
import io.github.kavishkamk.configuration.StatePublisherConfig;
import io.github.kavishkamk.util.AWSV4Auth;
import io.quarkus.logging.Log;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.inject.RestClient;

import java.net.URI;
import java.util.Map;
import java.util.TreeMap;

@ApplicationScoped
public class StatePublisher {

	StatePublisherConfig publisherConfig;

	@RestClient
	private final AWSIoTDeviceProxy awsIoTDeviceProxy;

	private final ShadowConfig shadowConfig;


	public StatePublisher(StatePublisherConfig publisherConfig, ShadowConfig shadowConfig) {
		this.publisherConfig = publisherConfig;
		this.awsIoTDeviceProxy = RestClientBuilder
				.newBuilder()
				.baseUri(URI.create("https://" + publisherConfig.endpoint()))
				.build(AWSIoTDeviceProxy.class);
		this.shadowConfig = shadowConfig;
	}

	// publish the status update to device shadow throw its REST API end point
	public Uni<Void> publishDeviceShadowUpdate(String deviceRef, String payload) {

		Map<String, String> headers = getHeaders("POST", deviceRef, payload);
		Log.debug("headers: " + headers);

		if(headers.isEmpty()) {
			Log.error("Exit from function, header list is empty");
			return Uni.createFrom().nullItem();
		}

		return awsIoTDeviceProxy
				.publishState(headers.get("x-amz-date"), headers.get("authorization"),
						deviceRef, shadowConfig.deviceShadow(),  payload)
				.onItem()
				.transformToUni(response -> {
					Log.debug("reserved response: " + response);
					Log.info("publish action to device shadow");
					return Uni.createFrom().nullItem();
				});

	}

	// get headers for the iot device shadow REST API request
	public Map<String, String> getHeaders(String httpMethodName, String deviceRef, String payload) {

		TreeMap<String, String> awsHeaders = new TreeMap<>();
		TreeMap<String, String> param = new TreeMap<>();

		awsHeaders.put("host", publisherConfig.endpoint());
		param.put("name", shadowConfig.deviceShadow());

		String regionServiceName = "iotdata";
		AWSV4Auth awsV4Auth =
				new AWSV4Auth.Builder( publisherConfig.awsAccessKeyId(), publisherConfig.awsSecretKey())
						.regionName(publisherConfig.region())
						.serviceName(regionServiceName)
						.httpMethodName(httpMethodName)
						.canonicalURI("/things/" + deviceRef + "/shadow")
						.awsHeaders(awsHeaders)
						.queryParameters(param)
						.payload(payload)
						.build();

		return awsV4Auth.getHeaders();
	}

}

