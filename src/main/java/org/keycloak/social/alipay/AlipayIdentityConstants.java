package org.keycloak.social.alipay;

/**
 * ALiPayIdentityConstants.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/06/23 15:36
 */
public class AlipayIdentityConstants {

  public static final String DEFAULT_SCOPE = "auth_user";

  public static final String THREE_PART_AUTH_URL =
      "https://openauth.alipay.com/oauth2/appToAppAuth.htm";
  public static final String WEB_AUTH_URL =
      "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm";

  /**
   * JSON 应格式.
   */
  public static final String FORMAT_JSON = "json";
  /**
   * sha256WithRsa 算法请求类型.
   */
  public static final String SIGN_TYPE_RSA2 = "RSA2";
  /**
   * 生产认证url.
   */
  public static final String SERVER_URL = "https://openapi.alipay.com/gateway.do";

  public static final String ALIPAY_PARAMETER_STATE = "state";
  public static final String ALIPAY_PARAMETER_APP_ID = "app_id";
  public static final String ALIPAY_PARAMETER_SOURCE = "source";
  public static final String ALIPAY_PARAMETER_USER_OUTPUTS = "userOutputs";
  public static final String ALIPAY_PARAMETER_SCOPE = "scope";
  public static final String ALIPAY_PARAMETER_ALIPAY_TOKEN = "alipay_token";
  public static final String ALIPAY_PARAMETER_AUTH_CODE = "auth_code";
}
