package org.keycloak.social.alipay;

import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.CertAlipayRequest;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.request.AlipayUserInfoShareRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.alipay.api.response.AlipayUserInfoShareResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import org.apache.commons.io.FileUtils;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

/**
 * ALiPayIdentityProvider.
 * 实现IdentityProvider为theme\base\admin\resources\js\controllers\realm.js中removeUsedSocial方法及.
 * ServerInfoAdminResource#setIdentityProviders(org.keycloak.representations.info.ServerInfoRepresentation)
 * 可重复新增身份提供者.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/19 15:24
 */
public class AlipayIdentityProvider
    extends AbstractOAuth2IdentityProvider<AlipayOAuth2IdentityProviderConfig>
    implements IdentityProvider<AlipayOAuth2IdentityProviderConfig> {

  public AlipayIdentityProvider(
      KeycloakSession session, AlipayOAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return super.callback(realm, callback, event);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  public BrokeredIdentityContext getFederatedIdentity(
      AlipayClient alipayClient, AlipaySystemOauthTokenResponse alipaySystemOauthTokenResponse) {
    if (!alipaySystemOauthTokenResponse.isSuccess()) {
      throw new IdentityBrokerException(
          "No access token available in OAuth server response: " + alipaySystemOauthTokenResponse);
    }
    BrokeredIdentityContext context = null;
    try {
      String accessToken = alipaySystemOauthTokenResponse.getAccessToken();
      String userId = alipaySystemOauthTokenResponse.getUserId();
      String expiresIn = alipaySystemOauthTokenResponse.getExpiresIn();
      String refreshToken = alipaySystemOauthTokenResponse.getRefreshToken();
      String template = " accessToken:%s \n alipayUserId:%s \n expiresIn:%s \n refreshToken:%s";
      System.out.println(String.format(template, accessToken, userId, expiresIn, refreshToken));
      AlipayUserInfoShareRequest infoShareRequest = new AlipayUserInfoShareRequest();

      AlipayUserInfoShareResponse alipayUserInfoShareResponse =
          alipayClient.certificateExecute(infoShareRequest, accessToken);
      JsonNode profile =
          new ObjectMapper().readTree(mapper.writeValueAsString(alipayUserInfoShareResponse));
      logger.info("get userInfo =" + profile.toString());
      context = AlipayIdentityProvider.this.extractIdentityFromProfile(null, profile);
      context
          .getContextData()
          .put(FEDERATED_ACCESS_TOKEN, alipaySystemOauthTokenResponse.getAccessToken());
    } catch (IOException | AlipayApiException e) {
      logger.error(e);
    }
    return context;
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      String aliPayApplicationType = this.getConfig().getAliPayApplicationType();
      String url;
      switch (aliPayApplicationType) {
        case "web":
          url =
              AlipayIdentityConstants.WEB_AUTH_URL
                  + "?app_id="
                  + this.getConfig().getClientId()
                  + "&scope="
                  + request.getHttpRequest().getAttribute("scope")
                  + "&state="
                  + request.getState().getEncoded()
                  + "&redirect_uri="
                  + request.getRedirectUri();
          break;
        case "three_part":
          url =
              AlipayIdentityConstants.THREE_PART_AUTH_URL
                  + "?app_id="
                  + this.getConfig().getClientId()
                  + "&application_type="
                  + request.getHttpRequest().getAttribute("scope")
                  + "&state="
                  + request.getState().getEncoded()
                  + "&redirect_uri="
                  + request.getRedirectUri();
          break;
        default:
          throw new UnsupportedOperationException();
      }
      URI authenticationUrl = URI.create(url);

      return Response.seeOther(authenticationUrl).build();
    } catch (Exception e) {
      throw new IdentityBrokerException("Could send authentication request to twitter.", e);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return AlipayIdentityConstants.DEFAULT_SCOPE;
  }

  protected AlipaySystemOauthTokenResponse getRefreshTokenRequest(
      AlipayClient alipayClient, String refreshToken) throws AlipayApiException {
    AlipaySystemOauthTokenRequest alipaySystemOauthTokenRequest =
        new AlipaySystemOauthTokenRequest();
    alipaySystemOauthTokenRequest.setGrantType(OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
    alipaySystemOauthTokenRequest.setCode(refreshToken);
    return alipayClient.certificateExecute(alipaySystemOauthTokenRequest);
  }

  protected class Endpoint {

    protected AuthenticationCallback callback;
    protected RealmModel realm;
    protected EventBuilder event;

    @Context protected KeycloakSession session;

    @Context protected ClientConnection clientConnection;

    @Context protected HttpHeaders headers;

    @Context protected UriInfo uriInfo;

    public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
      this.callback = callback;
      this.realm = realm;
      this.event = event;
    }

    @GET
    public Response authResponse(
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_STATE) String state,
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_APP_ID) String appId,
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_SOURCE)
            String source,
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_USER_OUTPUTS)
            String userOutputs,
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_SCOPE) String scope,
        @DefaultValue("") @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_ALIPAY_TOKEN)
            String alipayToken,
        @QueryParam(AlipayIdentityConstants.ALIPAY_PARAMETER_AUTH_CODE) String authCode) {

      logger.infov(
          AlipayIdentityConstants.APLIPAY_CALLBACK_TEMPLATE_LOG,
          state,
          appId,
          source,
          userOutputs,
          scope,
          alipayToken,
          authCode);

      try {
        BrokeredIdentityContext federatedIdentity;
        if (authCode != null) {
          AlipayClient alipayClient = this.generateAlipayClient();
          AlipaySystemOauthTokenResponse alipaySystemOauthTokenResponse =
              this.generateTokenRequest(alipayClient, authCode);
          federatedIdentity =
              AlipayIdentityProvider.this.getFederatedIdentity(
                  alipayClient, alipaySystemOauthTokenResponse);

          if (AlipayIdentityProvider.this.getConfig().isStoreToken()) {
            if (federatedIdentity.getToken() == null) {
              federatedIdentity.setToken(alipaySystemOauthTokenResponse.getAccessToken());
            }
          }

          federatedIdentity.setIdpConfig(AlipayIdentityProvider.this.getConfig());
          federatedIdentity.setIdp(AlipayIdentityProvider.this);
          federatedIdentity.setCode(state);

          return this.callback.authenticated(federatedIdentity);
        }
      } catch (Exception e) {
        logger.error("Failed to make identity provider oauth callback", e);
      }
      this.event.event(EventType.LOGIN);
      this.event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
      return ErrorPage.error(
          this.session,
          null,
          Response.Status.BAD_GATEWAY,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    public AlipayClient generateAlipayClient() throws AlipayApiException, IOException {
      CertAlipayRequest certAlipayRequest = new CertAlipayRequest();
      certAlipayRequest.setServerUrl(AlipayConstants.SERVER_URL);
      certAlipayRequest.setAppId(AlipayIdentityProvider.this.getConfig().getClientId());
      String privateKey =
          FileUtils.readFileToString(
              new File(AlipayIdentityProvider.this.getConfig().getAppPrivateKeyPath()),
              StandardCharsets.UTF_8.displayName());
      certAlipayRequest.setPrivateKey(privateKey);
      certAlipayRequest.setFormat(AlipayConstants.FORMAT_JSON);
      certAlipayRequest.setCharset(StandardCharsets.UTF_8.displayName());
      certAlipayRequest.setSignType(AlipayConstants.SIGN_TYPE);
      certAlipayRequest.setCertPath(AlipayIdentityProvider.this.getConfig().getAppCertPath());
      certAlipayRequest.setAlipayPublicCertPath(
          AlipayIdentityProvider.this.getConfig().getAlipayPublicCertPath());
      certAlipayRequest.setRootCertPath(
          AlipayIdentityProvider.this.getConfig().getAliPayRootCertPath());
      return new DefaultAlipayClient(certAlipayRequest);
    }

    private AlipaySystemOauthTokenResponse generateTokenRequest(
        AlipayClient alipayClient, String authCode) throws AlipayApiException {
      AlipaySystemOauthTokenRequest alipaySystemOauthTokenRequest =
          new AlipaySystemOauthTokenRequest();
      alipaySystemOauthTokenRequest.setGrantType(OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
      alipaySystemOauthTokenRequest.setCode(authCode);

      return alipayClient.certificateExecute(alipaySystemOauthTokenRequest);
    }
  }
}
