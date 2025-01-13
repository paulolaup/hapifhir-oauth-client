package usr.paulolaup.fhir.client.interceptor.oauth.test_config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;

import java.io.IOException;

public record TestConfig(FhirServerConfig fhirServer, AuthServerConfig authServer) {
    private static final String CONFIG_FILENAME = "test-config.yaml";
    private static final TestConfig INSTANCE;

    @JsonCreator
    public TestConfig(
            @JsonProperty("fhirServer") FhirServerConfig fhirServer,
            @JsonProperty("authServer") AuthServerConfig authServer) {
        this.fhirServer = fhirServer;
        this.authServer = authServer;
    }

    static {
        try {
            INSTANCE = initialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static TestConfig initialize() throws Exception {
        final var classLoader = TestConfig.class.getClassLoader();
        final var mapper = new YAMLMapper();
        try {
            return mapper.readValue(classLoader.getResourceAsStream(CONFIG_FILENAME), TestConfig.class);
        } catch (IOException exc) {
            throw new Exception("Failed to read config file " + CONFIG_FILENAME, exc);
        }
    }

    public static TestConfig getInstance() {
        return INSTANCE;
    }
}
