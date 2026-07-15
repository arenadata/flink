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

package org.apache.flink.runtime.webmonitor.history;

import org.apache.flink.api.common.JobID;
import org.apache.flink.api.common.JobStatus;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.HistoryServerOptions;
import org.apache.flink.configuration.HistoryServerOptions.HistoryServerWebAuthenticationType;
import org.apache.flink.runtime.history.FsJobArchivist;
import org.apache.flink.runtime.rest.messages.JobsOverviewHeaders;
import org.apache.flink.runtime.security.KerberosUtils;
import org.apache.flink.test.util.SecureTestEnvironment;

import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivilegedExceptionAction;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** MiniKDC-backed integration tests for HistoryServer SPNEGO authentication. */
class HistoryServerSpnegoIntegrationTest {

    @TempDir private Path tempDir;

    @Test
    void shouldProtectJobsOverviewWithSpnego() throws Exception {
        SecureTestEnvironment.prepare(tempDir.resolve("kdc").toFile(), "HTTP/localhost");

        HistoryServer historyServer = null;
        try {
            Path archiveDir = Files.createDirectories(tempDir.resolve("archive"));
            Path webDir = Files.createDirectories(tempDir.resolve("web"));
            JobID jobId = JobID.generate();
            createArchive(archiveDir, jobId);

            CountDownLatch archiveCreated = new CountDownLatch(1);
            historyServer =
                    new HistoryServer(
                            createHistoryServerConfiguration(archiveDir, webDir),
                            event -> {
                                if (event.getType()
                                        == HistoryServerArchiveFetcher.ArchiveEventType.CREATED) {
                                    archiveCreated.countDown();
                                }
                            });
            historyServer.start();

            assertThat(archiveCreated.await(10L, TimeUnit.SECONDS)).isTrue();

            URL jobsOverviewUrl =
                    new URL(
                            "http://localhost:"
                                    + historyServer.getWebPort()
                                    + JobsOverviewHeaders.URL);

            assertUnauthenticatedRequestIsChallenged(jobsOverviewUrl);

            String response = getWithSpnego(jobsOverviewUrl);

            assertThat(response).contains(jobId.toString());
        } finally {
            if (historyServer != null) {
                historyServer.stop();
            }
            SecureTestEnvironment.cleanup();
        }
    }

    private static Configuration createHistoryServerConfiguration(Path archiveDir, Path webDir) {
        Configuration configuration = new Configuration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_ARCHIVE_DIRS, archiveDir.toUri().toString());
        configuration.set(HistoryServerOptions.HISTORY_SERVER_WEB_DIR, webDir.toString());
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_ARCHIVE_REFRESH_INTERVAL,
                Duration.ofMillis(100L));
        configuration.set(HistoryServerOptions.HISTORY_SERVER_WEB_PORT, 0);
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TYPE,
                HistoryServerWebAuthenticationType.KERBEROS);
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "HTTP/localhost@" + SecureTestEnvironment.getRealm());
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                SecureTestEnvironment.getTestKeytab());
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET,
                "shared-secret");
        return configuration;
    }

    private static void assertUnauthenticatedRequestIsChallenged(URL url) throws IOException {
        RawHttpResponse response = getRaw(url, null);

        assertThat(response.statusLine).contains(" 401 ");
        assertThat(response.headers.toLowerCase(Locale.ROOT))
                .contains(
                        KerberosAuthenticator.WWW_AUTHENTICATE.toLowerCase(Locale.ROOT)
                                + ": "
                                + KerberosAuthenticator.NEGOTIATE.toLowerCase(Locale.ROOT));
    }

    private static String getWithSpnego(URL url) throws Exception {
        Subject clientSubject = loginClientSubject();
        return Subject.doAs(
                clientSubject,
                (PrivilegedExceptionAction<String>)
                        () -> {
                            GSSContext gssContext = null;
                            try {
                                GSSManager gssManager = GSSManager.getInstance();
                                String servicePrincipal =
                                        org.apache.hadoop.security.authentication.util.KerberosUtil
                                                .getServicePrincipal("HTTP", url.getHost());
                                GSSName serviceName =
                                        gssManager.createName(
                                                servicePrincipal,
                                                org.apache.hadoop.security.authentication.util
                                                        .KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID);
                                gssContext =
                                        gssManager.createContext(
                                                serviceName,
                                                org.apache.hadoop.security.authentication.util
                                                        .KerberosUtil.GSS_KRB5_MECH_OID,
                                                null,
                                                GSSContext.DEFAULT_LIFETIME);
                                gssContext.requestCredDeleg(true);
                                gssContext.requestMutualAuth(true);

                                byte[] outToken = gssContext.initSecContext(new byte[0], 0, 0);
                                assertThat(outToken).isNotNull();

                                RawHttpResponse response =
                                        getRaw(
                                                url,
                                                KerberosAuthenticator.NEGOTIATE
                                                        + " "
                                                        + Base64.getEncoder()
                                                                .encodeToString(outToken));
                                assertThat(response.statusLine).contains(" 200 ");
                                assertThat(response.headers.toLowerCase(Locale.ROOT))
                                        .contains("set-cookie: hadoop.auth=");
                                return response.body;
                            } finally {
                                if (gssContext != null) {
                                    gssContext.dispose();
                                }
                            }
                        });
    }

    private static RawHttpResponse getRaw(URL url, String authorizationHeader) throws IOException {
        try (Socket socket = new Socket(url.getHost(), url.getPort())) {
            socket.setSoTimeout(10_000);
            try (OutputStream outputStream = socket.getOutputStream();
                    InputStream inputStream = socket.getInputStream()) {
                StringBuilder request =
                        new StringBuilder()
                                .append("GET ")
                                .append(url.getFile())
                                .append(" HTTP/1.1\r\nHost: ")
                                .append(url.getHost())
                                .append("\r\nConnection: close\r\n");
                if (authorizationHeader != null) {
                    request.append(KerberosAuthenticator.AUTHORIZATION)
                            .append(": ")
                            .append(authorizationHeader)
                            .append("\r\n");
                }
                request.append("\r\n");

                outputStream.write(request.toString().getBytes(StandardCharsets.US_ASCII));
                outputStream.flush();

                String response = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
                int firstLineEnd = response.indexOf("\r\n");
                int headerEnd = response.indexOf("\r\n\r\n");
                assertThat(firstLineEnd).isGreaterThan(0);
                assertThat(headerEnd).isGreaterThan(firstLineEnd);
                return new RawHttpResponse(
                        response.substring(0, firstLineEnd),
                        response.substring(firstLineEnd + 2, headerEnd),
                        response.substring(headerEnd + 4));
            }
        }
    }

    private static Subject loginClientSubject() throws LoginException {
        Subject subject = new Subject();
        LoginContext loginContext =
                new LoginContext(
                        "",
                        subject,
                        (CallbackHandler) null,
                        new javax.security.auth.login.Configuration() {
                            @Override
                            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                                return new AppConfigurationEntry[] {
                                    KerberosUtils.keytabEntry(
                                            SecureTestEnvironment.getTestKeytab(),
                                            "client/localhost@" + SecureTestEnvironment.getRealm())
                                };
                            }
                        });
        loginContext.login();
        return subject;
    }

    private static void createArchive(Path archiveDir, JobID jobId) throws IOException {
        ArchivedJson archivedJson = new ArchivedJson("/joboverview", createJobOverviewJson(jobId));
        FsJobArchivist.archiveJob(
                new org.apache.flink.core.fs.Path(archiveDir.toUri()),
                jobId,
                Collections.singleton(archivedJson));
    }

    private static String createJobOverviewJson(JobID jobId) {
        return "{"
                + "\"finished\":[{"
                + "\"jid\":\""
                + jobId
                + "\","
                + "\"name\":\"spnego-test\","
                + "\"state\":\""
                + JobStatus.FINISHED.name()
                + "\","
                + "\"start-time\":0,"
                + "\"end-time\":1,"
                + "\"duration\":1,"
                + "\"last-modification\":1,"
                + "\"tasks\":{"
                + "\"total\":0,"
                + "\"created\":0,"
                + "\"deploying\":0,"
                + "\"scheduled\":0,"
                + "\"running\":0,"
                + "\"finished\":0,"
                + "\"canceling\":0,"
                + "\"canceled\":0,"
                + "\"failed\":0"
                + "}}]}";
    }

    private static final class RawHttpResponse {

        private final String statusLine;
        private final String headers;
        private final String body;

        private RawHttpResponse(String statusLine, String headers, String body) {
            this.statusLine = statusLine;
            this.headers = headers;
            this.body = body;
        }
    }
}
