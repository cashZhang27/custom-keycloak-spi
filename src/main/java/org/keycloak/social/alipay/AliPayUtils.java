package org.keycloak.social.alipay;

import com.alipay.api.internal.util.StreamUtil;
import com.alipay.api.internal.util.StringUtils;
import com.alipay.api.internal.util.codec.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 支付宝工具类.
 *
 * @author Cash Zhang
 * @version v1.0
 * @since 2020/07/02 16:20
 */
public class AliPayUtils {

  private static BouncyCastleProvider provider;

  static {
    provider = new BouncyCastleProvider();
    Security.addProvider(provider);
  }

  public static X509Certificate getCertFromContent(String certContent) {
    try {
      InputStream inputStream = new ByteArrayInputStream(certContent.getBytes());
      CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
      return (X509Certificate) cf.generateCertificate(inputStream);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String getCertSN(X509Certificate x509Certificate) {
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(
          (x509Certificate.getIssuerX500Principal().getName() + x509Certificate.getSerialNumber())
              .getBytes());
      String certSN = new BigInteger(1, md.digest()).toString(16);
      // BigInteger会把0省略掉，需补全至32位
      certSN = fillMD5(certSN);
      return certSN;
    } catch (NoSuchAlgorithmException e) {
      // TODO
      throw new RuntimeException(e);
    }
  }

  /**
   * 获取根证书序列号.
   *
   * @param rootCertContent
   * @return
   */
  public static String getRootCertSN(String rootCertContent) {
    StringBuffer sb = new StringBuffer();
    String certSN;
    try {
      X509Certificate[] x509Certificates = readPemCertChain(rootCertContent);
      MessageDigest md = MessageDigest.getInstance("MD5");
      for (X509Certificate c : x509Certificates) {
        if (c.getSigAlgOID().startsWith("1.2.840.113549.1.1")) {
          md.update((c.getIssuerX500Principal().getName() + c.getSerialNumber()).getBytes());
          certSN = new BigInteger(1, md.digest()).toString(16);
          // BigInteger会把0省略掉，需补全至32位
          certSN = fillMD5(certSN);

          sb.append("_").append(certSN);
        }
      }
    } catch (Exception e) {
      // TODO 提取根证书失败
    }
    String rootCertSN = sb.toString();
    if (rootCertSN.startsWith("_")) {
      rootCertSN = rootCertSN.substring(1);
    }
    return rootCertSN;
  }

  private static X509Certificate[] readPemCertChain(String cert) {
    try {
      ByteArrayInputStream inputStream = new ByteArrayInputStream(cert.getBytes());
      CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
      Collection<? extends Certificate> certificates = cf.generateCertificates(inputStream);

      return certificates.toArray(new X509Certificate[0]);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static String fillMD5(String md5) {
    return md5.length() == 32 ? md5 : fillMD5("0" + md5);
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

  public static String getSignContent(Map<String, String> sortedParams) {
    StringBuilder content = new StringBuilder();
    List<String> keys = new ArrayList<>(sortedParams.keySet());
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

  protected static String doSign(String content, String privateKey) throws Exception {
    PrivateKey priKey =
        getPrivateKeyFromPKCS8(
            AlipayConstants.SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));

    Signature signature = Signature.getInstance(AlipayConstants.SIGN_SHA256RSA_ALGORITHMS);

    signature.initSign(priKey);

    signature.update(content.getBytes(StandardCharsets.UTF_8));

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

  /**
   * 获取POST请求的base url.
   *
   * @param protocalMustParams 协议必输参数
   * @param protocalOptParams 协议可选参数
   * @return url
   */
  public static String getRequestUrl(
      Map<String, String> protocalMustParams, Map<String, String> protocalOptParams) {
    StringBuilder urlSb = new StringBuilder(AlipayConstants.SERVER_URL);
    try {
      String sysMustQuery = buildQuery(protocalMustParams);

      String sysOptQuery = buildQuery(protocalOptParams);

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

  public static String buildQuery(Map<String, String> params) throws IOException {
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
        query
            .append(name)
            .append("=")
            .append(URLEncoder.encode(value, StandardCharsets.UTF_8.displayName()));
      }
    }

    return query.toString();
  }
}
