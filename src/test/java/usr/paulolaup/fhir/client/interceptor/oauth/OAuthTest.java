package usr.paulolaup.fhir.client.interceptor.oauth;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import usr.paulolaup.fhir.client.interceptor.oauth.test_config.TestConfig;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class OAuthTest
{
    public static final FhirContext FHIR_CONTEXT = FhirContext.forR4();

    private final URI fhirServerUrl;
    private final URI tokenAccessUrl;
    private final String clientId;
    private final String clientSecret;
    private final Map<String, String> authorization;

    public OAuthTest(String clientId) throws Exception {
        final var config = TestConfig.getInstance();
        this.fhirServerUrl = config.fhirServer().baseUrl();

        final var authServerConfig = config.authServer();
        this.tokenAccessUrl = authServerConfig.tokenAccessUrl();

        final var oClient = authServerConfig.clients().stream().filter((c) -> c.id().equals(clientId)).findAny();
        if (oClient.isEmpty()) throw new Exception("No such client config entry for client ID " + clientId);
        else {
            final var client = oClient.get();
            this.clientId = client.id();
            this.clientSecret = client.secret();
            this.authorization = client.authorization();
        }
    }

    public URI getFhirServerUrl()
    {
        return fhirServerUrl;
    }

    public URI getTokenAccessUrl()
    {
        return tokenAccessUrl;
    }

    public String getClientId()
    {
        return clientId;
    }

    public String getClientSecret()
    {
        return clientSecret;
    }

    public Map<String, String> getAuthorization()
    {
        return authorization;
    }

    protected static void checkRequestHeader(IHttpRequest request)
    {
        final var headers = request.getAllHeaders();
        assertTrue(headers.containsKey("Authorization"),
                "The request should contain an Authorization header");

        final var authHeader = headers.get("Authorization");
        assertTrue(authHeader.stream().anyMatch((it) -> it.matches("^Bearer .+$")),
                "Authorization header should contain at least one bearer token entry with a non-empty token");
    }
}
