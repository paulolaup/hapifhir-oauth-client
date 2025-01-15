package usr.paulolaup.fhir.client.interceptor.oauth.test_config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.List;

public record AuthServerConfig(
        URI tokenAccessUrl,
        List<ClientConfig> clients
) {
    @JsonCreator
    public static AuthServerConfig of(
            @JsonProperty("tokenAccessUrl") URI tokenAccessUrl,
            @JsonProperty("clients") List<ClientConfig> clients
    ) {
        return new AuthServerConfig(tokenAccessUrl, clients);
    }
}
