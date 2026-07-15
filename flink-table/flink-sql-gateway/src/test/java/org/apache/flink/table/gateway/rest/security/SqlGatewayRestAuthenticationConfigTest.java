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
import org.apache.flink.configuration.RestOptions;
import org.apache.flink.table.gateway.api.endpoint.SqlGatewayEndpointFactoryUtils;
import org.apache.flink.table.gateway.rest.SqlGatewayRestEndpointFactory;
import org.apache.flink.table.gateway.rest.util.SqlGatewayRestOptions;
import org.apache.flink.table.gateway.rest.util.SqlGatewayRestOptions.SqlGatewayRestAuthenticationType;
import org.apache.flink.util.ConfigurationException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for {@link SqlGatewayRestAuthenticationConfig}. */
class SqlGatewayRestAuthenticationConfigTest {

    @Test
    void shouldDefaultToNone() throws Exception {
        SqlGatewayRestAuthenticationConfig config =
                SqlGatewayRestAuthenticationConfig.fromConfiguration(baseConfiguration());

        assertThat(config.type()).isEqualTo(SqlGatewayRestAuthenticationType.NONE);
        assertThat(config.isKerberosEnabled()).isFalse();
    }

    @Test
    void shouldNotInstallHandlerWhenAuthenticationIsDisabled() throws Exception {
        assertThat(
                        new SqlGatewaySpnegoAuthenticationHandlerFactory()
                                .createHandler(baseConfiguration(), Collections.emptyMap()))
                .isEmpty();
    }

    @Test
    void shouldRequirePrincipalForKerberos() {
        Configuration configuration = baseConfiguration();
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "KERBEROS");
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB.key(), "/tmp/a");

        assertThatThrownBy(
                        () -> SqlGatewayRestAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("authentication.kerberos.principal");
    }

    @Test
    void shouldRequireKeytabForKerberos() {
        Configuration configuration = baseConfiguration();
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "KERBEROS");
        set(
                configuration,
                SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key(),
                "HTTP/localhost@EXAMPLE.COM");

        assertThatThrownBy(
                        () -> SqlGatewayRestAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("authentication.kerberos.keytab");
    }

    @Test
    void shouldRejectBothInlineSecretAndSecretFile(@TempDir Path tempDir) throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "secret-file", StandardCharsets.UTF_8);

        Configuration configuration = baseConfiguration();
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "KERBEROS");
        set(
                configuration,
                SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key(),
                "HTTP/localhost@EXAMPLE.COM");
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB.key(), "/tmp/a");
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET.key(), "secret");
        set(
                configuration,
                SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE.key(),
                secretFile.toString());

        assertThatThrownBy(
                        () -> SqlGatewayRestAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("signature.secret")
                .hasMessageContaining("signature.secret-file");
    }

    @Test
    void shouldReadSecretFile(@TempDir Path tempDir) throws Exception {
        Path secretFile = tempDir.resolve("secret");
        Files.writeString(secretFile, "secret-file\n", StandardCharsets.UTF_8);

        Configuration configuration = kerberosConfiguration();
        set(
                configuration,
                SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE.key(),
                secretFile.toString());

        SqlGatewayRestAuthenticationConfig config =
                SqlGatewayRestAuthenticationConfig.fromConfiguration(configuration);

        assertThat(new String(config.signatureSecret(), StandardCharsets.UTF_8))
                .isEqualTo("secret-file");
    }

    @Test
    void shouldReplaceHostPattern() throws Exception {
        String principal =
                SqlGatewaySpnegoAuthenticator.replaceHostPattern(
                        "HTTP/_HOST@EXAMPLE.COM", "localhost");

        assertThat(principal).startsWith("HTTP/");
        assertThat(principal).endsWith("@EXAMPLE.COM");
        assertThat(principal).doesNotContain("_HOST");
    }

    @Test
    void shouldRejectInvalidAuthenticationType() {
        Configuration configuration = baseConfiguration();
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "BASIC");

        assertThatThrownBy(
                        () -> SqlGatewayRestAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("BASIC");
    }

    private static Configuration kerberosConfiguration() {
        Configuration configuration = baseConfiguration();
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_TYPE.key(), "KERBEROS");
        set(
                configuration,
                SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key(),
                "HTTP/localhost@EXAMPLE.COM");
        set(configuration, SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB.key(), "/tmp/a");
        return configuration;
    }

    private static Configuration baseConfiguration() {
        Configuration configuration = new Configuration();
        configuration.set(RestOptions.ADDRESS, "localhost");
        return configuration;
    }

    private static void set(Configuration configuration, String localKey, String value) {
        configuration.setString(
                SqlGatewayEndpointFactoryUtils.getSqlGatewayOptionPrefix(
                                SqlGatewayRestEndpointFactory.IDENTIFIER)
                        + localKey,
                value);
    }
}
