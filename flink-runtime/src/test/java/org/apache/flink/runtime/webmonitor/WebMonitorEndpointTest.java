/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.runtime.webmonitor;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.RestOptions;
import org.apache.flink.configuration.WebOptions;
import org.apache.flink.core.testutils.OneShotLatch;
import org.apache.flink.runtime.blob.NoOpTransientBlobService;
import org.apache.flink.runtime.leaderelection.StandaloneLeaderElection;
import org.apache.flink.runtime.rest.handler.RestHandlerConfiguration;
import org.apache.flink.runtime.rest.handler.legacy.metrics.VoidMetricFetcher;
import org.apache.flink.runtime.util.TestingFatalErrorHandler;
import org.apache.flink.runtime.webmonitor.security.JobManagerAuthenticatedUserHeaders;
import org.apache.flink.util.ConfigurationException;
import org.apache.flink.util.ExecutorUtils;

import org.junit.jupiter.api.Test;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for the {@link WebMonitorEndpoint}. */
class WebMonitorEndpointTest {

    @Test
    void cleansUpExpiredExecutionGraphs() throws Exception {
        final Configuration configuration = new Configuration();
        configuration.set(RestOptions.ADDRESS, "localhost");
        configuration.set(RestOptions.BIND_PORT, "0");
        configuration.set(WebOptions.REFRESH_INTERVAL, Duration.ofMillis(5L));
        final ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        final long timeout = 10000L;

        final OneShotLatch cleanupLatch = new OneShotLatch();
        final TestingExecutionGraphCache executionGraphCache =
                TestingExecutionGraphCache.newBuilder()
                        .setCleanupRunnable(cleanupLatch::trigger)
                        .build();
        try (final WebMonitorEndpoint<RestfulGateway> webMonitorEndpoint =
                new WebMonitorEndpoint<>(
                        CompletableFuture::new,
                        configuration,
                        RestHandlerConfiguration.fromConfiguration(configuration),
                        CompletableFuture::new,
                        NoOpTransientBlobService.INSTANCE,
                        executor,
                        VoidMetricFetcher.INSTANCE,
                        new StandaloneLeaderElection(UUID.randomUUID()),
                        executionGraphCache,
                        new TestingFatalErrorHandler())) {

            webMonitorEndpoint.start();

            // check that the cleanup will be triggered
            cleanupLatch.await(timeout, TimeUnit.MILLISECONDS);
        } finally {
            ExecutorUtils.gracefulShutdown(timeout, TimeUnit.MILLISECONDS, executor);
        }
    }

    @Test
    void exposesAuthenticatedUserEndpointWhenWebAuthenticationIsDisabled() throws Exception {
        final Configuration configuration = new Configuration();
        configuration.set(RestOptions.ADDRESS, "localhost");
        configuration.set(RestOptions.BIND_PORT, "0");
        final ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        final long timeout = 10000L;

        try (final WebMonitorEndpoint<RestfulGateway> webMonitorEndpoint =
                new WebMonitorEndpoint<>(
                        CompletableFuture::new,
                        configuration,
                        RestHandlerConfiguration.fromConfiguration(configuration),
                        CompletableFuture::new,
                        NoOpTransientBlobService.INSTANCE,
                        executor,
                        VoidMetricFetcher.INSTANCE,
                        new StandaloneLeaderElection(UUID.randomUUID()),
                        TestingExecutionGraphCache.newBuilder().build(),
                        new TestingFatalErrorHandler())) {

            webMonitorEndpoint.start();

            HttpURLConnection connection =
                    (HttpURLConnection)
                            new URI(
                                            "http",
                                            null,
                                            "localhost",
                                            webMonitorEndpoint.getServerAddress().getPort(),
                                            JobManagerAuthenticatedUserHeaders.URL,
                                            null,
                                            null)
                                    .toURL()
                                    .openConnection();
            connection.setRequestMethod("GET");

            assertThat(connection.getResponseCode()).isEqualTo(200);
            assertThat(
                            new String(
                                    connection.getInputStream().readAllBytes(),
                                    StandardCharsets.UTF_8))
                    .contains("\"authenticated\":false");
        } finally {
            ExecutorUtils.gracefulShutdown(timeout, TimeUnit.MILLISECONDS, executor);
        }
    }

    @Test
    void failsFastForInvalidKerberosWebAuthenticationConfiguration() throws Exception {
        final Configuration configuration = new Configuration();
        configuration.set(RestOptions.ADDRESS, "localhost");
        configuration.set(
                WebOptions.AUTHENTICATION_TYPE, WebOptions.WebAuthenticationType.KERBEROS);
        final ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        final long timeout = 10000L;

        try {
            assertThatThrownBy(
                            () ->
                                    new WebMonitorEndpoint<>(
                                            CompletableFuture::new,
                                            configuration,
                                            RestHandlerConfiguration.fromConfiguration(
                                                    configuration),
                                            CompletableFuture::new,
                                            NoOpTransientBlobService.INSTANCE,
                                            executor,
                                            VoidMetricFetcher.INSTANCE,
                                            new StandaloneLeaderElection(UUID.randomUUID()),
                                            TestingExecutionGraphCache.newBuilder().build(),
                                            new TestingFatalErrorHandler()))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining(WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key());
        } finally {
            ExecutorUtils.gracefulShutdown(timeout, TimeUnit.MILLISECONDS, executor);
        }
    }
}
