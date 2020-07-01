package org.keycloak.social.alipay;

import com.alipay.api.internal.util.StreamUtil;
import com.alipay.api.internal.util.StringUtils;
import com.alipay.api.internal.util.WebUtils;
import com.alipay.api.internal.util.codec.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;

/**
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/07/01 20:38
 */
public class Test {

  public static void main(String[] args) throws Exception {
    String authCode = "de9dbe3dccea49f1af10a7011eacQX79";
    String appId = "";
    String appCertSN = "";
    String alipayRootCertSN = "";
    String privateKey = "";
    long beginTime = System.currentTimeMillis();

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
    protocalMustParams.put(AlipayConstants.CHARSET, "utf-8");
    protocalMustParams.put(AlipayConstants.APP_CERT_SN, appCertSN);
    protocalMustParams.put(AlipayConstants.ALIPAY_ROOT_CERT_SN, alipayRootCertSN);
    Long timestamp = System.currentTimeMillis();
    DateFormat df = new SimpleDateFormat(AlipayConstants.DATE_TIME_FORMAT);
    df.setTimeZone(TimeZone.getTimeZone(AlipayConstants.DATE_TIMEZONE));
    protocalMustParams.put(AlipayConstants.TIMESTAMP, df.format(new Date(timestamp)));

    Map<String, String> protocalOptParams = new HashMap<>();

    protocalOptParams.put(AlipayConstants.FORMAT, "json");

    Map<String, String> sortedMap = getSortedMap(appParams, protocalMustParams, protocalOptParams);
    String signContent = getSignContent(sortedMap);

    protocalMustParams.put(AlipayConstants.SIGN, doSign(signContent, "utf-8", privateKey));

    String url = getRequestUrl(protocalMustParams, protocalOptParams);

    Map<String, Object> result = new HashMap<>();

    result.put("prepareTime", System.currentTimeMillis());
    String rsp =
        WebUtils.doPost(
            url,
            appParams,
            "utf-8",
            AlipayConstants.CONNECT_TIMEOUT,
            AlipayConstants.READ_TIMEOUT,
            null,
            0);
    result.put("requestTime", System.currentTimeMillis());
    result.put("rsp", rsp);
    result.put("textParams", appParams);
    result.put("protocalMustParams", protocalMustParams);
    result.put("protocalOptParams", protocalOptParams);
    result.put("url", url);

    Map<String, Long> costTimeMap = new HashMap<>();
    if (result.containsKey("prepareTime")) {
      costTimeMap.put("prepareCostTime", (Long) (result.get("prepareTime")) - beginTime);
      if (result.containsKey("requestTime")) {
        costTimeMap.put(
            "requestCostTime",
            (Long) (result.get("requestTime")) - (Long) (result.get("prepareTime")));
      }
    }

    // checkResponseCertSign(request, parser, responseItem.getRespContent(), tRsp.isSuccess());
    if (costTimeMap.containsKey("requestCostTime")) {
      costTimeMap.put(
          "postCostTime", System.currentTimeMillis() - (Long) (result.get("requestTime")));
    }
    System.out.println(result);
  }

  protected static String doSign(String content, String charset, String privateKey)
      throws Exception {
    PrivateKey priKey =
        getPrivateKeyFromPKCS8(
            AlipayConstants.SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));

    Signature signature = Signature.getInstance(AlipayConstants.SIGN_ALGORITHMS);

    signature.initSign(priKey);

    if (StringUtils.isEmpty(charset)) {
      signature.update(content.getBytes());
    } else {
      signature.update(content.getBytes(charset));
    }

    byte[] signed = signature.sign();

    return new String(Base64.encodeBase64(signed));
  }

  public static PrivateKey getPrivateKeyFromPKCS8(String algorithm, InputStream ins)
      throws Exception {
    if (ins == null || StringUtils.isEmpty(algorithm)) {
      return null;
    }

    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

    byte[] encodedKey = StreamUtil.readText(ins).getBytes();

    encodedKey = Base64.decodeBase64(encodedKey);

    return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
  }

  public static String getSignContent(Map<String, String> sortedParams) {
    StringBuilder content = new StringBuilder();
    List<String> keys = new ArrayList<String>(sortedParams.keySet());
    Collections.sort(keys);
    int index = 0;
    for (String key : keys) {
      String value = sortedParams.get(key);
      if (StringUtils.areNotEmpty(key, value)) {
        content.append(index == 0 ? "" : "&").append(key).append("=").append(value);
        index++;
      }
    }
    return content.toString();
  }

  public static Map<String, String> getSortedMap(
      Map<String, String> appParams,
      Map<String, String> protocalMustParams,
      Map<String, String> protocalOptParams) {
    Map<String, String> sortedParams = new TreeMap<>();
    if (appParams != null && appParams.size() > 0) {
      sortedParams.putAll(appParams);
    }
    if (protocalMustParams != null && protocalMustParams.size() > 0) {
      sortedParams.putAll(protocalMustParams);
    }
    if (protocalOptParams != null && protocalOptParams.size() > 0) {
      sortedParams.putAll(protocalOptParams);
    }

    return sortedParams;
  }

  /**
   * 获取POST请求的base url.
   *
   * @param protocalMustParams 协议必输参数
   * @param protocalOptParams  协议可选参数
   * @return url
   */
  private static String getRequestUrl(
      Map<String, String> protocalMustParams, Map<String, String> protocalOptParams) {
    StringBuilder urlSb = new StringBuilder(AlipayConstants.SERVER_URL);
    try {
      String sysMustQuery = buildQuery(protocalMustParams, "utf-8");

      String sysOptQuery = buildQuery(protocalOptParams, "utf-8");

      urlSb.append("?");
      urlSb.append(sysMustQuery);
      if (sysOptQuery != null && sysOptQuery.length() > 0) {
        urlSb.append("&");
        urlSb.append(sysOptQuery);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    return urlSb.toString();
  }

  public static String buildQuery(Map<String, String> params, String charset) throws IOException {
    if (params == null || params.isEmpty()) {
      return null;
    }

    StringBuilder query = new StringBuilder();
    Set<Entry<String, String>> entries = params.entrySet();
    boolean hasParam = false;

    for (Entry<String, String> entry : entries) {
      String name = entry.getKey();
      String value = entry.getValue();
      // 忽略参数名或参数值为空的参数
      if (StringUtils.areNotEmpty(name, value)) {
        if (hasParam) {
          query.append("&");
        } else {
          hasParam = true;
        }

        query.append(name).append("=").append(URLEncoder.encode(value, charset));
      }
    }

    return query.toString();
  }

  public static String getCertSN(X509Certificate cf) {
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update((cf.getIssuerX500Principal().getName() + cf.getSerialNumber()).getBytes());
      String certSN = new BigInteger(1, md.digest()).toString(16);
      // BigInteger会把0省略掉，需补全至32位
      certSN = fillMD5(certSN);
      return certSN;
    } catch (NoSuchAlgorithmException e) {
      // TODO
      throw new RuntimeException(e);
    }
  }

  private static String fillMD5(String md5) {
    return md5.length() == 32 ? md5 : fillMD5("0" + md5);
  }
}
