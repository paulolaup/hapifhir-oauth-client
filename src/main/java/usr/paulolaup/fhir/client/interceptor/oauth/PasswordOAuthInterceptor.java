package usr.paulolaup.fhir.client.interceptor.oauth;

import org.apache.commons.lang3.Validate;
import org.apache.http.NameValuePair;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;

import javax.annotation.Nonnull;
import java.util.List;

public class PasswordOAuthInterceptor extends OAuthInterceptor {

    private final UsernamePasswordCredentials myUsernameAndPassword;

    public PasswordOAuthInterceptor(final @Nonnull String theAccessTokenUrl,
                                    final @Nonnull UsernamePasswordCredentials theClientCredentials,
                                    final @Nonnull UsernamePasswordCredentials theUsernameAndPassword) {
        super(theAccessTokenUrl, theClientCredentials);
        Validate.notNull(theUsernameAndPassword, "theUsernameAndPassword must not be null");
        myUsernameAndPassword = theUsernameAndPassword;
    }

    @Override
    public List<NameValuePair> getGrantTypeSpecificParameters() {
        return List.of(new BasicNameValuePair("username", myUsernameAndPassword.getUserName()),
                new BasicNameValuePair("password", myUsernameAndPassword.getPassword()),
                new BasicNameValuePair("grant_type", "password"));
    }

}
