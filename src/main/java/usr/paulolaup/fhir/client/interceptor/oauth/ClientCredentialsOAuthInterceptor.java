package usr.paulolaup.fhir.client.interceptor.oauth;

import org.apache.http.NameValuePair;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;

import javax.annotation.Nonnull;
import java.util.List;

public class ClientCredentialsOAuthInterceptor extends OAuthInterceptor {

    public ClientCredentialsOAuthInterceptor(final @Nonnull String theAccessTokenUrl,
                                             final @Nonnull UsernamePasswordCredentials theClientCredentials) {
        super(theAccessTokenUrl, theClientCredentials);
    }

    @Override
    public List<NameValuePair> getGrantTypeSpecificParameters() {
        return List.of(new BasicNameValuePair("grant_type", "client_credentials"));
    }

}
