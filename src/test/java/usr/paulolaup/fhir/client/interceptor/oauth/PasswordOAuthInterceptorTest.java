package usr.paulolaup.fhir.client.interceptor.oauth;

import ca.uhn.fhir.rest.api.Constants;
import ca.uhn.fhir.rest.api.EncodingEnum;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import ca.uhn.fhir.rest.client.apache.ApacheRestfulClientFactory;
import ca.uhn.fhir.rest.client.api.ClientResponseContext;
import ca.uhn.fhir.rest.client.api.Header;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PasswordOAuthInterceptorTest extends OAuthTest
{
    private final UsernamePasswordCredentials myClientCredentials;
    private final UsernamePasswordCredentials myUsernameAndPassword;

    public PasswordOAuthInterceptorTest() throws Exception
    {
        super("password-credentials");
        myClientCredentials = new UsernamePasswordCredentials(getClientId(), getClientSecret());
        final var auth = getAuthorization();
        myUsernameAndPassword = new UsernamePasswordCredentials(auth.get("username"), auth.get("password"));
    }

    @Test
    void constructorTest()
    {
        assertThrows(NullPointerException.class, () -> {
            new PasswordOAuthInterceptor(null, myClientCredentials, myUsernameAndPassword);
        });
        assertThrows(NullPointerException.class, () -> {
            new PasswordOAuthInterceptor(getTokenAccessUrl().toString(), null, myUsernameAndPassword);
        });
        assertThrows(NullPointerException.class, () -> {
            new PasswordOAuthInterceptor(getTokenAccessUrl().toString(), myClientCredentials, null);
        });
    }

    @Test
    void getGrantTypeSpecificParametersTest()
    {
        final var interceptor = new PasswordOAuthInterceptor(
                getTokenAccessUrl().toString(), myClientCredentials, myUsernameAndPassword
        );
        final var expected = List.of(new BasicNameValuePair("username", myUsernameAndPassword.getUserName()),
                new BasicNameValuePair("password", myUsernameAndPassword.getPassword()),
                new BasicNameValuePair("grant_type", "password"));

        assertEquals(expected, interceptor.getGrantTypeSpecificParameters());
    }

    @Test
    void interceptRequestTest()
    {
        final var interceptor = new PasswordOAuthInterceptor(
                getTokenAccessUrl().toString(), myClientCredentials, myUsernameAndPassword
        );
        final var clientFactory = new ApacheRestfulClientFactory(FHIR_CONTEXT);
        final var client = clientFactory.getHttpClient(
                new StringBuilder().append(getFhirServerUrl().toString()),
                Collections.emptyMap(),
                null,
                RequestTypeEnum.GET,
                List.of(new Header("Content-Type", Constants.CT_FHIR_JSON_NEW))
        );
        final var request =  client.createGetRequest(FHIR_CONTEXT, EncodingEnum.JSON);

        assertDoesNotThrow(() -> interceptor.interceptRequest(request),
                "The access token (refresh) request failed");

        checkRequestHeader(request);
    }

    @Test
    void interceptResponseTest()
    {
        final var interceptor = new PasswordOAuthInterceptor(
                getTokenAccessUrl().toString(), myClientCredentials, myUsernameAndPassword
        );
        final var clientFactory = new ApacheRestfulClientFactory(FHIR_CONTEXT);
        final var client = clientFactory.getHttpClient(
                new StringBuilder().append(getFhirServerUrl().toString()),
                Collections.emptyMap(),
                null,
                RequestTypeEnum.GET,
                List.of(new Header("Content-Type", Constants.CT_FHIR_JSON_NEW))
        );
        final var request =  client.createGetRequest(FHIR_CONTEXT, EncodingEnum.JSON);
        request.setUri(getFhirServerUrl().resolve("metadata").toString());

        assertDoesNotThrow(() -> {
            final var response = request.execute();
            final var context = new ClientResponseContext(
                    request, response, null, FHIR_CONTEXT, CapabilityStatement.class);

            interceptor.interceptRequest(request);
            interceptor.interceptResponse(request, response, null, context);

            final var newResponse = context.getHttpResponse();
            checkRequestHeader(context.getHttpRequest());
            assertEquals(200, newResponse.getStatus(),
                    "Unexpected status code in response");

            final var parser = FHIR_CONTEXT.newJsonParser();
            final var resource = parser.parseResource(
                    EntityUtils.toString(((HttpResponse) newResponse.getResponse()).getEntity()));
            assertInstanceOf(CapabilityStatement.class, resource,
                    "Unexpected FHIR resource type in response body");
        }, "The request execution was unsuccessful");
    }

    @Test
    public void integrationTest()
    {
        final var interceptor = new PasswordOAuthInterceptor(
                getTokenAccessUrl().toString(), myClientCredentials, myUsernameAndPassword
        );
        final var client = FHIR_CONTEXT.newRestfulGenericClient(getFhirServerUrl().toString());
        client.registerInterceptor(interceptor);

        assertDoesNotThrow(() -> client.capabilities().ofType(CapabilityStatement.class).execute(),
                "The integration test failed");
    }
}