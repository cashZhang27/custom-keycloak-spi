package org.keycloak.social.alipay;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * AbstractIdentityProviderFactory.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/19 15:26
 */
public class ALiPayIdentityProviderFactory
    extends AbstractIdentityProviderFactory<ALiPayIdentityProvider>
    implements SocialIdentityProviderFactory<ALiPayIdentityProvider> {

  public static final String PROVIDER_ID = "alipay";

  @Override
  public String getName() {
    return "ALiPay";
  }

  @Override
  public ALiPayIdentityProvider create(
      KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
    return new ALiPayIdentityProvider(
        keycloakSession, new ALiPayOAuth2IdentityProviderConfig(identityProviderModel));
  }

  @Override
  public OAuth2IdentityProviderConfig createConfig() {
    return new OAuth2IdentityProviderConfig();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
