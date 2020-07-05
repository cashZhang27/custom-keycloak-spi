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

  private String getKey(String key) {
    return this.getConfig().get(key);
  }

  private void setKey(String key, String value) {
    this.getConfig().put(key, value);
  }

  public String getAppCertPath() {
    return this.getKey("appCertPath");
  }

  public void setAppCertPath(String appCertPath) {
    this.setKey("appCertPath", appCertPath);
  }

  public String getAliPayRootCertContent() {
    return this.getKey("aliPayRootCertContent");
  }

  public void setAliPayRootCertContent(String aliPayRootCertContent) {
    this.setKey("aliPayRootCertContent", aliPayRootCertContent);
  }

  public String getAliPayRootCertPath() {
    return this.getKey("aliPayRootCertPath");
  }

  public void setAliPayRootCertPath(String aliPayRootCertPath) {
    this.setKey("aliPayRootCertPath", aliPayRootCertPath);
  }

  public String getAppPrivateKeyPath() {
    return this.getKey("appPrivateKeyPath");
  }

  public void setAppPrivateKeyPath(String appPrivateKeyPath) {
    this.setKey("appPrivateKeyPath", appPrivateKeyPath);
  }

  public String getAliPayApplicationType() {
    return this.getKey("aliPayApplicationType");
  }

  public void setAliPayApplicationType(String aliPayApplicationType) {
    this.setKey("aliPayApplicationType", aliPayApplicationType);
  }

  public String getAlipayPublicCertPath() {
    return this.getKey("alipayPublicCertPath");
  }

  public void setAlipayPublicCertPath(String alipayPublicCertPath) {
    this.setKey("alipayPublicCertPath", alipayPublicCertPath);
  }

  public String getAlipayPublicCertContent() {
    return this.getKey("alipayPublicCertContent");
  }

  public void setAlipayPublicCertContent(String alipayPublicCertContent) {
    this.setKey("alipayPublicCertContent", alipayPublicCertContent);
  }
}
