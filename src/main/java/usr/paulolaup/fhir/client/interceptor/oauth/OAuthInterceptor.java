package usr.paulolaup.fhir.client.interceptor.oauth;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.client.api.ClientResponseContext;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import ca.uhn.fhir.rest.client.api.IHttpResponse;
import ca.uhn.fhir.rest.client.api.IRestfulClient;
import ca.uhn.fhir.util.CoverageIgnore;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.Validate;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Interceptor
public abstract class OAuthInterceptor {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<HashMap<String, Object>> MAPPER_TYPE_REF = new TypeReference<>() {};

    private final HttpClient myClient = HttpClientBuilder.create().build();
    private final String myAccessTokenUrl;
    private final UsernamePasswordCredentials myClientCredentials;

    private String myAccessToken = null;

    @CoverageIgnore
    public OAuthInterceptor(final @Nonnull String theAccessTokenUrl,
                            final @Nonnull UsernamePasswordCredentials theClientCredentials) {
        Validate.notNull(theAccessTokenUrl, "theAccessTokenUrl must not be null");
        Validate.notNull(theClientCredentials, "theClientCredentials must not be null");
        myAccessTokenUrl = theAccessTokenUrl;
        myClientCredentials = theClientCredentials;
    }

    private void refreshAccessToken() throws AuthenticationException {
        try {
            final var response = myClient.execute(buildAccessTokenRequest());
            final var statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                final var map = (Map<String, Object>) MAPPER.readValue(response.getEntity().getContent(), MAPPER_TYPE_REF);
                final var token = map.get("access_token");
                if (token == null) throw new Exception("No field 'access_token' in response");
                else myAccessToken = (String) token;
                updateGrantTypeSpecificParameters(map);
            } else {
                myAccessToken = null;
                throw new HttpResponseException(statusCode, buildErrorMessage(response));
            }
        } catch (Exception exc) {
            throw new AuthenticationException("Failed to retrieve fresh access token", exc);
        }
    }

    private NameValuePair buildAuthorizationHeader() throws AuthenticationException {
        if (myAccessToken == null) refreshAccessToken();
        return new BasicNameValuePair("Authorization", "Bearer " + myAccessToken);
    }

    private HttpPost buildAccessTokenRequest() throws UnsupportedEncodingException {
        final var httpPost = new HttpPost(myAccessTokenUrl);
        final var params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("client_id", myClientCredentials.getUserName()));
        params.add(new BasicNameValuePair("client_secret", myClientCredentials.getPassword()));
        params.addAll(getGrantTypeSpecificParameters());
        httpPost.setEntity(new UrlEncodedFormEntity(params));
        return httpPost;
    }

    @Hook(Pointcut.CLIENT_REQUEST)
    public void interceptRequest(final IHttpRequest theRequest) throws AuthenticationException {
        final var header = buildAuthorizationHeader();
        theRequest.addHeader(header.getName(), header.getValue());
    }

    @Hook(Pointcut.CLIENT_RESPONSE)
    public void interceptResponse(final IHttpRequest theRequest, final IHttpResponse theResponse,
                                  final IRestfulClient theClient, final ClientResponseContext theContext
    ) throws IOException, AuthenticationException {
        if (theResponse.getStatus() == 401 /*Unauthorized*/) refreshAccessToken();
        theContext.setHttpResponse(theRequest.execute());
    }

    public abstract List<NameValuePair> getGrantTypeSpecificParameters();

    public void updateGrantTypeSpecificParameters(final Map<String, Object> theResponseFields) {
        // Implement this method if the access token request parameters change over time
    }

    private static String buildErrorMessage(final HttpResponse theResponse) throws IOException {
        try {
            final var map = (Map<String, Object>) MAPPER.readValue(theResponse.getEntity().getContent(), MAPPER_TYPE_REF);
            final var errorType = (String) map.get("error");
            final var description = (String) map.get("error_description");
            final var uri = (String) map.get("error_uri");
            final var sb = new StringBuilder().append("Error type '").append(errorType).append("'");
            if (description != null) sb.append(": ").append(description);
            if (uri != null) sb.append(". See ").append(uri);
            return sb.toString();
        }  catch (Exception exc) {
            return new String(theResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}