package usr.paulolaup.fhir.client.interceptor.oauth.test_config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.Map;

public record ClientConfig(
        String id,
        String secret,
        Map<String, String> authorization
) {
    @JsonCreator
    public static ClientConfig of(
            @JsonProperty("id") String id,
            @JsonProperty("secret") String secret,
            @JsonProperty("authorization") Map<String, String> authorization
    ) {
        return new ClientConfig(id, secret, authorization);
    }
}
