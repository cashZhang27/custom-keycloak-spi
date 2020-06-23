package org.keycloak.social.alipay;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

/**
 * ALiPayIdentityProvider.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/19 15:24
 */
public class ALiPayIdentityProvider
    extends AbstractOAuth2IdentityProvider<ALiPayOAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<ALiPayOAuth2IdentityProviderConfig> {

  public ALiPayIdentityProvider(
      KeycloakSession session, ALiPayOAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  protected String getDefaultScopes() {
    return ALiPayIdentityConstants.DEFAULT_SCOPE;
  }
}
