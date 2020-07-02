package org.keycloak.social.alipay;

import com.alipay.api.internal.util.WebUtils;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;

/**
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/07/01 20:38
 */
public class Test {

  private static final String APP_PRIVATE_KEY = "";

  public static void main(String[] args) throws Exception {
    String authCode = "6c35ba0b246c4bfc9a32545967edSX79";
    String appId = "";
    String appCertSN = "";
    String alipayRootCertSN = "";

    X509Certificate certFromContent = AliPayUtils.getCertFromContent("");
    String certSN = AliPayUtils.getCertSN(certFromContent);
    System.out.println(appCertSN.equals(certSN));
    String rootCertSN = AliPayUtils.getRootCertSN("");
    System.out.println(alipayRootCertSN.equals(rootCertSN));
    long beginTime =
        LocalDateTime.now()
            .atZone(
                ZoneId.ofOffset(
                    AlipayConstants.ZONE_PREFIX_GMT,
                    ZoneOffset.ofHours(AlipayConstants.ZONE_OFFSET_SHANGHAI)))
            .toEpochSecond();

    Map<String, String> appParams = new HashMap<>();
    appParams.put("code", authCode);
    appParams.put(
        "grant_type", AbstractOAuth2IdentityProvider.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

    Map<String, String> protocalMustParams = new HashMap<>();
    protocalMustParams.put(
        AlipayConstants.METHOD, AlipayConstants.ALIPAY_SYSTEM_OAUTH_TOKEN_API_METHOD_NAME);
    protocalMustParams.put(AlipayConstants.VERSION, AlipayConstants.VERSION_V1);
    protocalMustParams.put(AlipayConstants.APP_ID, appId);
    protocalMustParams.put(AlipayConstants.SIGN_TYPE, AlipayConstants.SIGN_TYPE_RSA2);
    protocalMustParams.put(AlipayConstants.CHARSET, StandardCharsets.UTF_8.displayName());
    protocalMustParams.put(AlipayConstants.APP_CERT_SN, appCertSN);
    protocalMustParams.put(AlipayConstants.ALIPAY_ROOT_CERT_SN, alipayRootCertSN);
    String timestamp =
        LocalDateTime.now()
            .atZone(
                ZoneId.ofOffset(
                    AlipayConstants.ZONE_PREFIX_GMT,
                    ZoneOffset.ofHours(AlipayConstants.ZONE_OFFSET_SHANGHAI)))
            .format(DateTimeFormatter.ofPattern(AlipayConstants.DATE_TIME_FORMAT));
    protocalMustParams.put(AlipayConstants.TIMESTAMP, timestamp);

    Map<String, String> protocalOptParams = new HashMap<>();

    protocalOptParams.put(AlipayConstants.FORMAT, AlipayConstants.FORMAT_JSON);

    Map<String, String> sortedMap =
        AliPayUtils.getSortedMap(appParams, protocalMustParams, protocalOptParams);
    String signContent = AliPayUtils.getSignContent(sortedMap);
    protocalMustParams.put(AlipayConstants.SIGN, AliPayUtils.doSign(signContent, APP_PRIVATE_KEY));

    String url = AliPayUtils.getRequestUrl(protocalMustParams, protocalOptParams);

    Map<String, Object> result = new HashMap<>();
    long prepareTime =
        LocalDateTime.now()
            .atZone(
                ZoneId.ofOffset(
                    AlipayConstants.ZONE_PREFIX_GMT,
                    ZoneOffset.ofHours(AlipayConstants.ZONE_OFFSET_SHANGHAI)))
            .toEpochSecond();
    result.put("prepareTime", prepareTime);
    String rsp =
        WebUtils.doPost(
            url,
            appParams,
            StandardCharsets.UTF_8.displayName(),
            AlipayConstants.CONNECT_TIMEOUT,
            AlipayConstants.READ_TIMEOUT,
            null,
            0);
    long requestTime =
        LocalDateTime.now()
            .atZone(
                ZoneId.ofOffset(
                    AlipayConstants.ZONE_PREFIX_GMT,
                    ZoneOffset.ofHours(AlipayConstants.ZONE_OFFSET_SHANGHAI)))
            .toEpochSecond();
    result.put("requestTime", requestTime);
    result.put("rsp", rsp);
    result.put("textParams", appParams);
    result.put("protocalMustParams", protocalMustParams);
    result.put("protocalOptParams", protocalOptParams);
    result.put("url", url);

    Map<String, Long> costTimeMap = new HashMap<>();
    if (result.containsKey("prepareTime")) {
      costTimeMap.put("prepareCostTime", prepareTime - beginTime);
      if (result.containsKey("requestTime")) {
        costTimeMap.put("requestCostTime", requestTime - prepareTime);
      }
    }

    // checkResponseCertSign(request, parser, responseItem.getRespContent(), tRsp.isSuccess());
    if (costTimeMap.containsKey("requestCostTime")) {
      costTimeMap.put(
          "postCostTime",
          LocalDateTime.now()
                  .atZone(
                      ZoneId.ofOffset(
                          AlipayConstants.ZONE_PREFIX_GMT,
                          ZoneOffset.ofHours(AlipayConstants.ZONE_OFFSET_SHANGHAI)))
                  .toEpochSecond()
              - requestTime);
    }
    System.out.println(result);
  }
}
