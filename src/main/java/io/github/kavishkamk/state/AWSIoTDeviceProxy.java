package io.github.kavishkamk.state;

import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@Path("/things")
@Produces(MediaType.APPLICATION_JSON)
@RegisterRestClient(configKey = "aws-iot-device-api")
public interface AWSIoTDeviceProxy {

    /*
     * this is the api request call for update the device shadow desired state
     */
    @POST
    @Path("/{deviceRef}/shadow")
    Uni<JsonObject> publishState(
            @HeaderParam("x-amz-date") String xAmzDate,
            @HeaderParam("authorization") String authorization,
            @PathParam("deviceRef") String deviceRef,
            @QueryParam("name") String name,
            String message);

}
