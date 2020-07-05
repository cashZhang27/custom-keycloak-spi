1. 将com.zip解压拷贝至KEYCLOAK_HOME

   docker举例

   `docker cp com keycloak:/opt/jboss/keycloak/modules`

2. 将 realm-identity-provider-alipay.html 拷贝至 KEYCLOAK_HOME/themes/base/admin/resources/partials

   docker举例

   `docker cp realm-identity-provider-alipay.html keycloak:/opt/jboss/keycloak/themes/base/admin/resources/partials`

3. 注册模块

   - `                <provider>module:com.cashzhang27.custom-keycloak-spi</provider>`

   ```xml
           <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
               <web-context>auth</web-context>
               <providers>
                   <provider>classpath:${jboss.home.dir}/providers/*</provider>
                   <provider>module:com.cashzhang27.custom-keycloak-spi</provider>
               </providers>
               …………
           </subsystem>
   ```

   - 拷贝至KEYCLOAK_HOME/standalone/configuration/

     `docker cp keycloak:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml standalone-ha.xml`

     vi 修改文件

     `docker cp standalone-ha.xml keycloak:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml`

4. 拷贝证书

   ```bash
   docker exec -it -uroot keycloak bash
   mkdir /opt/alipay
   docker cp 2021001******* keycloak:/opt/alipay/2021001*******
   ```

5. 配置idp

   ![配置idp](src\main\resources\images\image-20200705201634603.png)
