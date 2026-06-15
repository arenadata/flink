/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.table.gateway.rest.security;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.runtime.security.KerberosUtils;
import org.apache.flink.table.gateway.api.session.SessionEnvironment;
import org.apache.flink.table.gateway.api.session.SessionHandle;
import org.apache.flink.table.gateway.api.utils.MockedSqlGatewayService;
import org.apache.flink.table.gateway.rest.SqlGatewayRestEndpoint;
import org.apache.flink.table.gateway.rest.util.SqlGatewayRestOptions;

import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Properties;

import static org.apache.flink.table.gateway.rest.util.SqlGatewayRestEndpointTestUtils.getBaseConfig;
import static org.apache.flink.table.gateway.rest.util.SqlGatewayRestEndpointTestUtils.getFlinkConfig;
import static org.apache.flink.table.gateway.rest.util.SqlGatewayRestEndpointTestUtils.getSqlGatewayRestOptionFullName;
import static org.assertj.core.api.Assertions.assertThat;

/** Integration tests for SQL Gateway REST SPNEGO authentication. */
class SqlGatewaySpnegoITCase {

    private static final MediaType JSON = MediaType.parse("application/json");
    private static final String HOST = "localhost";
    private static final String CLIENT_PRINCIPAL_NAME = "alice";
    private static final String HTTP_SERVICE_PRINCIPAL_NAME = "HTTP/" + HOST;

    @Test
    void shouldRequireSpnegoAndAllowKerberosClient(@TempDir Path tempDir) throws Exception {
        Properties previousProperties = rememberKerberosProperties();
        MiniKdc kdc = null;
        SqlGatewayRestEndpoint endpoint = null;
        LoginContext loginContext = null;
        try {
            Path kdcDir = tempDir.resolve("kdc");
            Files.createDirectories(kdcDir);
            Properties kdcConf = MiniKdc.createConf();
            kdcConf.setProperty(MiniKdc.KDC_BIND_ADDRESS, HOST);
            kdc = new MiniKdc(kdcConf, kdcDir.toFile());
            kdc.start();
            System.setProperty(MiniKdc.JAVA_SECURITY_KRB5_CONF, kdc.getKrb5conf().toString());
            System.setProperty("sun.security.krb5.disableReferrals", "true");

            Path serverKeytab = tempDir.resolve("server.keytab");
            Path clientKeytab = tempDir.resolve("client.keytab");
            kdc.createPrincipal(serverKeytab.toFile(), HTTP_SERVICE_PRINCIPAL_NAME);
            kdc.createPrincipal(clientKeytab.toFile(), CLIENT_PRINCIPAL_NAME);

            Configuration flinkConfig = getFlinkConfig(HOST, HOST, "0");
            setAuthOption(flinkConfig, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "KERBEROS");
            setAuthOption(
                    flinkConfig,
                    SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key(),
                    "*");
            setAuthOption(
                    flinkConfig,
                    SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB.key(),
                    serverKeytab.toString());
            setAuthOption(
                    flinkConfig,
                    SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET.key(),
                    "shared-test-secret");

            Configuration endpointConfig = getBaseConfig(flinkConfig);
            SqlGatewaySpnegoAuthenticationHandlerFactory.validateConfiguration(endpointConfig);
            endpoint = new SqlGatewayRestEndpoint(endpointConfig, new TestingSqlGatewayService());
            endpoint.start();
            String baseUrl = getBaseUrl(endpoint);

            OkHttpClient httpClient = new OkHttpClient();
            assertSpnegoChallenge(httpClient, new Request.Builder().url(baseUrl + "/v1/info"));
            assertSpnegoChallenge(
                    httpClient,
                    new Request.Builder()
                            .url(baseUrl + "/v1/sessions")
                            .post(RequestBody.create(JSON, "{}")));

            loginContext =
                    loginFromKeytab(
                            CLIENT_PRINCIPAL_NAME + "@" + kdc.getRealm(), clientKeytab);
            try (Response infoResponse =
                    spnegoRequest(
                            httpClient,
                            new Request.Builder().url(baseUrl + "/v1/info"),
                            loginContext.getSubject())) {
                assertThat(infoResponse.code()).isEqualTo(200);
                assertThat(infoResponse.header("Set-Cookie")).contains("hadoop.auth=");
            }

            try (Response openSessionResponse =
                    spnegoRequest(
                            httpClient,
                            new Request.Builder()
                                    .url(baseUrl + "/v1/sessions")
                                    .post(RequestBody.create(JSON, "{}")),
                            loginContext.getSubject())) {
                assertThat(openSessionResponse.code()).isEqualTo(200);
                assertThat(openSessionResponse.body().string()).contains("sessionHandle");
                assertThat(openSessionResponse.header("Set-Cookie")).contains("hadoop.auth=");
            }
        } finally {
            if (loginContext != null) {
                loginContext.logout();
            }
            if (endpoint != null) {
                endpoint.stop();
            }
            if (kdc != null) {
                kdc.stop();
            }
            restoreKerberosProperties(previousProperties);
        }
    }

    private static void assertSpnegoChallenge(OkHttpClient httpClient, Request.Builder builder)
            throws Exception {
        try (Response response = httpClient.newCall(builder.build()).execute()) {
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.header("WWW-Authenticate")).isEqualTo("Negotiate");
        }
    }

    private static Response spnegoRequest(
            OkHttpClient httpClient, Request.Builder builder, Subject clientSubject)
            throws Exception {
        return Subject.doAs(
                clientSubject,
                (PrivilegedExceptionAction<Response>)
                        () -> {
                            GSSManager gssManager = GSSManager.getInstance();
                            GSSName serverName =
                                    gssManager.createName(
                                            "HTTP@" + HOST, GSSName.NT_HOSTBASED_SERVICE);
                            GSSContext gssContext =
                                    gssManager.createContext(
                                            serverName,
                                            KerberosUtil.GSS_SPNEGO_MECH_OID,
                                            null,
                                            GSSContext.DEFAULT_LIFETIME);
                            try {
                                gssContext.requestMutualAuth(true);
                                byte[] clientToken = new byte[0];
                                for (int i = 0; i < 2; i++) {
                                    byte[] outputToken =
                                            gssContext.initSecContext(
                                                    clientToken, 0, clientToken.length);
                                    Request request =
                                            builder.header(
                                                            "Authorization",
                                                            "Negotiate "
                                                                    + Base64.getEncoder()
                                                                            .encodeToString(
                                                                                    outputToken))
                                                    .build();
                                    Response response = httpClient.newCall(request).execute();
                                    if (response.code() != 401) {
                                        return response;
                                    }
                                    String authenticateHeader =
                                            response.header("WWW-Authenticate", "Negotiate");
                                    response.close();
                                    clientToken = decodeServerToken(authenticateHeader);
                                }
                                throw new IllegalStateException(
                                        "SPNEGO authentication did not complete.");
                            } finally {
                                gssContext.dispose();
                            }
                        });
    }

    private static byte[] decodeServerToken(String authenticateHeader) {
        String prefix = "Negotiate ";
        if (!authenticateHeader.startsWith(prefix)) {
            return new byte[0];
        }
        return Base64.getDecoder().decode(authenticateHeader.substring(prefix.length()));
    }

    private static LoginContext loginFromKeytab(String principal, Path keytab) throws Exception {
        LoginContext loginContext =
                new LoginContext(
                        "client",
                        null,
                        null,
                        new javax.security.auth.login.Configuration() {
                            @Override
                            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                                return new AppConfigurationEntry[] {
                                    KerberosUtils.keytabEntry(keytab.toString(), principal)
                                };
                            }
                        });
        loginContext.login();
        return loginContext;
    }

    private static String getBaseUrl(SqlGatewayRestEndpoint endpoint) {
        InetSocketAddress serverAddress = endpoint.getServerAddress();
        return "http://" + serverAddress.getHostString() + ":" + serverAddress.getPort();
    }

    private static void setAuthOption(Configuration configuration, String localKey, String value) {
        configuration.setString(getSqlGatewayRestOptionFullName(localKey), value);
    }

    private static Properties rememberKerberosProperties() {
        Properties properties = new Properties();
        remember(properties, MiniKdc.JAVA_SECURITY_KRB5_CONF);
        remember(properties, "sun.security.krb5.disableReferrals");
        return properties;
    }

    private static void remember(Properties properties, String key) {
        String value = System.getProperty(key);
        if (value != null) {
            properties.setProperty(key, value);
        }
    }

    private static void restoreKerberosProperties(Properties properties) {
        restore(properties, MiniKdc.JAVA_SECURITY_KRB5_CONF);
        restore(properties, "sun.security.krb5.disableReferrals");
    }

    private static void restore(Properties properties, String key) {
        if (properties.containsKey(key)) {
            System.setProperty(key, properties.getProperty(key));
        } else {
            System.clearProperty(key);
        }
    }

    private static final class TestingSqlGatewayService extends MockedSqlGatewayService {
        @Override
        public SessionHandle openSession(SessionEnvironment environment) {
            return SessionHandle.create();
        }
    }
}
