package usr.paulolaup.fhir.client.interceptor.oauth.test_config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;

public record FhirServerConfig(
        URI baseUrl
) {
    @JsonCreator
    public static FhirServerConfig of(@JsonProperty("baseUrl") URI baseUrl)
    {
        return new FhirServerConfig(baseUrl);
    }

}
