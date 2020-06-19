package org.keycloak.social.alipay;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

/**
 * ALiPayIdentityProvider.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/19 15:24
 */
public class ALiPayIdentityProvider extends AbstractOAuth2IdentityProvider
    implements SocialIdentityProvider {

  public ALiPayIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  protected String getDefaultScopes() {
    return null;
  }
}
