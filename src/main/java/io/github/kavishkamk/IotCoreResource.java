package io.github.kavishkamk;

import io.github.kavishkamk.configuration.ShadowConfig;
import io.github.kavishkamk.state.StatePublisher;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@Tag(name = "AWS Iot Core Resources", description = "used to test aws iot core rest end pont with AWSV4 signin")
@Path("/iot-core-controller")
@ApplicationScoped
public class IotCoreResource {

    private final StatePublisher statePublisher;
    private final ShadowConfig shadowConfig;

    public IotCoreResource(StatePublisher statePublisher, ShadowConfig shadowConfig) {
        this.statePublisher = statePublisher;
        this.shadowConfig = shadowConfig;
    }

    @GET
    @Path("/with-sec-token")
    @Operation(operationId = "testWithToken", description = "Test the AWS IoT core device shadow REST end pont with AWSV4")
    public Uni<Response> testWithToken() {
        String message = getMessage();

        return statePublisher.publishDeviceShadowUpdate(shadowConfig.deviceRef(), message)
                .onItem().transform(unused -> Response.ok().build());
    }




    public String getMessage() {

        return "{\"state\":{\"desired\":{\"attributeRef\":1}}}";

    }
}
