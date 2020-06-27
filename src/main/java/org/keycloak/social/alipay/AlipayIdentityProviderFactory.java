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
public class AlipayIdentityProviderFactory
    extends AbstractIdentityProviderFactory<AlipayIdentityProvider>
    implements SocialIdentityProviderFactory<AlipayIdentityProvider> {

  public static final String PROVIDER_ID = "alipay";

  @Override
  public String getName() {
    return "ALiPay";
  }

  @Override
  public AlipayIdentityProvider create(
      KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
    return new AlipayIdentityProvider(
        keycloakSession, new AlipayOAuth2IdentityProviderConfig(identityProviderModel));
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
