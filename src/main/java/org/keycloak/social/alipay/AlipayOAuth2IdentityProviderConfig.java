package org.keycloak.social.alipay;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * ALiPayOAuth2IdentityProviderConfig.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/23 15:29
 */
public class AlipayOAuth2IdentityProviderConfig extends OAuth2IdentityProviderConfig {

  private static final long serialVersionUID = 5730387260641871357L;

  public AlipayOAuth2IdentityProviderConfig() {
    super();
  }

  public AlipayOAuth2IdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public String getKey(String key) {
    return this.getConfig().get(key);
  }

  public void setKey(String key) {
    this.getConfig().put("key", key);
  }

  public String getAppCertContent() {
    return this.getConfig().get("appCertContent");
  }

  public String getRootCertContent() {
    return this.getConfig().get("rootCertContent");
  }
}
