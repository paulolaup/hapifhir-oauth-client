package usr.paulolaup.fhir.client.interceptor.oauth;

import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import org.apache.http.NameValuePair;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

public class RefreshTokenOAuthInterceptor extends OAuthInterceptor {

    private String myRefreshToken = null;

    public RefreshTokenOAuthInterceptor(final @Nonnull String theAccessTokenUrl,
                                        final @Nonnull UsernamePasswordCredentials theClientCredentials) {
        super(theAccessTokenUrl, theClientCredentials);
    }

    @Override
    public List<NameValuePair> getGrantTypeSpecificParameters() {
        return List.of(new BasicNameValuePair("refresh_token", myRefreshToken),
                new BasicNameValuePair("grant_type", "refresh_token"));
    }

    @Override
    public void updateGrantTypeSpecificParameters(final Map<String, Object> theResponseFields) {
        final var refreshToken = theResponseFields.get("refresh_token");
        if (refreshToken == null) throw new AuthenticationException("No field 'refresh_token' in response");
        else myRefreshToken = (String) refreshToken;
    }

}
