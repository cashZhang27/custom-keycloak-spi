package org.keycloak.social.alipay;

import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.CertAlipayRequest;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.vault.VaultStringSecret;
import twitter4j.Twitter;
import twitter4j.TwitterFactory;
import twitter4j.auth.RequestToken;

/**
 * ALiPayIdentityProvider.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/19 15:24
 */
public class AlipayIdentityProvider
    extends AbstractOAuth2IdentityProvider<AlipayOAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<AlipayOAuth2IdentityProviderConfig> {

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

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode node) {
    return super.extractIdentityFromProfile(event, node);
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {
    String accessToken =
        this.extractTokenFromResponse(response, this.getAccessTokenResponseParameter());

    if (accessToken == null) {
      throw new IdentityBrokerException(
          "No access token available in OAuth server response: " + response);
    }

    BrokeredIdentityContext context = this.doGetFederatedIdentity(accessToken);
    context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
    return context;
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try (VaultStringSecret vaultStringSecret =
        this.session.vault().getStringSecret(this.getConfig().getClientSecret())) {
      Twitter twitter = new TwitterFactory().getInstance();
      twitter.setOAuthConsumer(
          this.getConfig().getClientId(),
          vaultStringSecret.get().orElse(this.getConfig().getClientSecret()));

      URI uri = new URI(request.getRedirectUri() + "?state=" + request.getState().getEncoded());

      RequestToken requestToken = twitter.getOAuthRequestToken(uri.toString());
      AuthenticationSessionModel authSession = request.getAuthenticationSession();

      // authSession.setAuthNote(TWITTER_TOKEN, requestToken.getToken());
      // authSession.setAuthNote(TWITTER_TOKENSECRET, requestToken.getTokenSecret());

      URI authenticationUrl = URI.create(requestToken.getAuthenticationURL());

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
      AlipayClient alipayClient, String refreshToken) {
    AlipaySystemOauthTokenRequest alipaySystemOauthTokenRequest =
        new AlipaySystemOauthTokenRequest();
    alipaySystemOauthTokenRequest.setGrantType(OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
    alipaySystemOauthTokenRequest.setCode(refreshToken);
    try {
      return alipayClient.certificateExecute(alipaySystemOauthTokenRequest);
    } catch (AlipayApiException e) {
      // TODO
      e.printStackTrace();
    }
    return null;
  }

  protected class Endpoint {

    protected AuthenticationCallback callback;
    protected RealmModel realm;
    protected EventBuilder event;

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected HttpHeaders headers;

    @Context
    protected UriInfo uriInfo;

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
        BrokeredIdentityContext federatedIdentity = null;
        if (authCode != null) {
          AlipayClient alipayClient = this.generateAlipayClient(appId);
          AlipaySystemOauthTokenResponse alipaySystemOauthTokenResponse =
              this.generateTokenRequest(alipayClient, authCode);
          // String response = this.generateTokenRequest(authorizationCode, wechatFlag).asString();
          // logger.info("response=" + response);
          // federatedIdentity =
          //     ALiPayIdentityProvider.this.getFederatedIdentity(response, wechatFlag);
          //
          // if (ALiPayIdentityProvider.this.getConfig().isStoreToken()) {
          //   if (federatedIdentity.getToken() == null) {
          //     federatedIdentity.setToken(response);
          //   }
          // }

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

    public AlipayClient generateAlipayClient(String appId) {
      try (VaultStringSecret vaultPrivateKeySecret =
          this.session
              .vault()
              .getStringSecret(AlipayIdentityProvider.this.getConfig().getClientSecret())) {
        CertAlipayRequest certAlipayRequest = new CertAlipayRequest();
        certAlipayRequest.setServerUrl(AlipayIdentityConstants.SERVER_URL);
        certAlipayRequest.setAppId(appId);
        certAlipayRequest.setPrivateKey(
            vaultPrivateKeySecret
                .get()
                .orElse(AlipayIdentityProvider.this.getConfig().getClientSecret()));
        certAlipayRequest.setFormat(AlipayIdentityConstants.ALIPAY_FORMAT);
        certAlipayRequest.setCharset(StandardCharsets.UTF_8.displayName());
        certAlipayRequest.setSignType(AlipayIdentityConstants.ALIPAY_SIGN_TYPE);

        return new DefaultAlipayClient(certAlipayRequest);
      } catch (AlipayApiException e) {
        e.printStackTrace();
      }
      return null;
    }

    private AlipaySystemOauthTokenResponse generateTokenRequest(
        AlipayClient alipayClient, String authCode) {
      AlipaySystemOauthTokenRequest alipaySystemOauthTokenRequest =
          new AlipaySystemOauthTokenRequest();
      alipaySystemOauthTokenRequest.setGrantType(OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
      alipaySystemOauthTokenRequest.setCode(authCode);
      try {
        return alipayClient.certificateExecute(alipaySystemOauthTokenRequest);
      } catch (AlipayApiException e) {
        // TODO
        e.printStackTrace();
      }
      return null;
    }

    public BrokeredIdentityContext getFederatedIdentity(String response, boolean wechat) {
      String accessToken =
          AlipayIdentityProvider.this.extractTokenFromResponse(
              response, AlipayIdentityProvider.this.getAccessTokenResponseParameter());
      if (accessToken == null) {
        throw new IdentityBrokerException(
            "No access token available in OAuth server response: " + response);
      }
      BrokeredIdentityContext context = null;
      try {
        JsonNode profile;
        if (wechat) {
          String openid = AlipayIdentityProvider.this.extractTokenFromResponse(response, "openid");
          String url = "PROFILE_URL".replace("ACCESS_TOKEN", accessToken).replace("OPENID", openid);
          // String url  ,= PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("OPENID",
          // openid);
          profile = SimpleHttp.doGet(url, this.session).asJson();
        } else {
          profile = new ObjectMapper().readTree(response);
        }
        logger.info("get userInfo =" + profile.toString());
        context = AlipayIdentityProvider.this.extractIdentityFromProfile(null, profile);
      } catch (IOException e) {
        logger.error(e);
      }
      context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
      return context;
    }
  }
}
