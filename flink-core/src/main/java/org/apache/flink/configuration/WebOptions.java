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

package org.apache.flink.configuration;

import org.apache.flink.annotation.PublicEvolving;
import org.apache.flink.annotation.docs.Documentation;
import org.apache.flink.configuration.description.Description;

import java.time.Duration;

import static org.apache.flink.configuration.ConfigOptions.key;
import static org.apache.flink.configuration.description.TextElement.code;

/** Configuration options for the WebMonitorEndpoint. */
@PublicEvolving
public class WebOptions {

    /** Config parameter defining the runtime monitor web-frontend server address. */
    @Deprecated
    public static final ConfigOption<String> ADDRESS =
            key("web.address")
                    .stringType()
                    .noDefaultValue()
                    .withDeprecatedKeys("jobmanager.web.address")
                    .withDescription("Address for runtime monitor web-frontend server.");

    /**
     * The port for the runtime monitor web-frontend server.
     *
     * @deprecated Use {@link RestOptions#PORT} instead
     */
    @Deprecated
    public static final ConfigOption<Integer> PORT =
            key("web.port").intType().defaultValue(8081).withDeprecatedKeys("jobmanager.web.port");

    /**
     * The config parameter defining the Access-Control-Allow-Origin header for all responses from
     * the web-frontend.
     */
    public static final ConfigOption<String> ACCESS_CONTROL_ALLOW_ORIGIN =
            key("web.access-control-allow-origin")
                    .stringType()
                    .defaultValue("*")
                    .withDeprecatedKeys("jobmanager.web.access-control-allow-origin")
                    .withDescription(
                            "Access-Control-Allow-Origin header for all responses from the web-frontend.");

    /** The config parameter defining the refresh interval for the web-frontend in milliseconds. */
    public static final ConfigOption<Duration> REFRESH_INTERVAL =
            key("web.refresh-interval")
                    .durationType()
                    .defaultValue(Duration.ofMillis(3000L))
                    .withDeprecatedKeys("jobmanager.web.refresh-interval")
                    .withDescription("Refresh interval for the web-frontend.");

    /** Config parameter to override SSL support for the JobManager Web UI. */
    @Deprecated
    public static final ConfigOption<Boolean> SSL_ENABLED =
            key("web.ssl.enabled")
                    .booleanType()
                    .defaultValue(true)
                    .withDeprecatedKeys("jobmanager.web.ssl.enabled")
                    .withDescription(
                            "Flag indicating whether to override SSL support for the JobManager Web UI.");

    /** The config parameter defining the flink web directory to be used by the webmonitor. */
    @Documentation.OverrideDefault("System.getProperty(\"java.io.tmpdir\")")
    public static final ConfigOption<String> TMP_DIR =
            key("web.tmpdir")
                    .stringType()
                    .defaultValue(System.getProperty("java.io.tmpdir"))
                    .withDeprecatedKeys("jobmanager.web.tmpdir")
                    .withDescription(
                            "Local directory that is used by the REST API for temporary files.");

    /**
     * The config parameter defining the directory for uploading the job jars. If not specified a
     * dynamic directory will be used under the directory specified by JOB_MANAGER_WEB_TMPDIR_KEY.
     */
    public static final ConfigOption<String> UPLOAD_DIR =
            key("web.upload.dir")
                    .stringType()
                    .noDefaultValue()
                    .withDeprecatedKeys("jobmanager.web.upload.dir")
                    .withDescription(
                            Description.builder()
                                    .text(
                                            "Local directory that is used by the REST API for storing uploaded jars. If not specified a dynamic directory will be created"
                                                    + " under %s.",
                                            code(TMP_DIR.key()))
                                    .build());

    /** The config parameter defining the number of archived jobs for the JobManager. */
    public static final ConfigOption<Integer> ARCHIVE_COUNT =
            key("web.history")
                    .intType()
                    .defaultValue(5)
                    .withDeprecatedKeys("jobmanager.web.history")
                    .withDescription("Number of archived jobs for the JobManager.");

    /**
     * The log file location (may be in /log for standalone but under log directory when using
     * YARN).
     */
    public static final ConfigOption<String> LOG_PATH =
            key("web.log.path")
                    .stringType()
                    .noDefaultValue()
                    .withDeprecatedKeys("jobmanager.web.log.path")
                    .withDescription(
                            "Path to the log file (may be in /log for standalone but under log directory when using YARN).");

    /** Config parameter indicating whether jobs can be uploaded and run from the web-frontend. */
    public static final ConfigOption<Boolean> SUBMIT_ENABLE =
            key("web.submit.enable")
                    .booleanType()
                    .defaultValue(true)
                    .withDeprecatedKeys("jobmanager.web.submit.enable")
                    .withDescription(
                            "Flag indicating whether jobs can be uploaded and run from the web-frontend.");

    /** Config parameter indicating whether jobs can be canceled from the web-frontend. */
    public static final ConfigOption<Boolean> CANCEL_ENABLE =
            key("web.cancel.enable")
                    .booleanType()
                    .defaultValue(true)
                    .withDescription(
                            "Flag indicating whether jobs can be canceled from the web-frontend.");

    /** Config parameter indicating whether jobs can be rescaled from the web-frontend. */
    public static final ConfigOption<Boolean> RESCALE_ENABLE =
            key("web.rescale.enable")
                    .booleanType()
                    .defaultValue(true)
                    .withDescription(
                            "Flag indicating whether jobs can be rescaled from the web-frontend.");

    /** Authentication type for the JobManager web-frontend. */
    public static final ConfigOption<WebAuthenticationType> AUTHENTICATION_TYPE =
            key("web.authentication.type")
                    .enumType(WebAuthenticationType.class)
                    .defaultValue(WebAuthenticationType.NONE)
                    .withDescription(
                            "Authentication type for the JobManager web frontend and REST "
                                    + "endpoints.");

    /** Kerberos principal for JobManager web SPNEGO authentication. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_PRINCIPAL =
            key("web.authentication.kerberos.principal")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Kerberos principal for JobManager web SPNEGO authentication. "
                                    + "Required when JobManager web authentication type is "
                                    + "KERBEROS. The principal must start with HTTP/. The _HOST "
                                    + "placeholder is replaced with the configured REST address. "
                                    + "Use * to accept all HTTP principals in the keytab.");

    /** Kerberos keytab for JobManager web SPNEGO authentication. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_KEYTAB =
            key("web.authentication.kerberos.keytab")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Absolute path to the keytab file for the JobManager web SPNEGO "
                                    + "principal. Required when JobManager web authentication "
                                    + "type is KERBEROS.");

    /** Kerberos auth-to-local rules for JobManager web SPNEGO authentication. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_NAME_RULES =
            key("web.authentication.kerberos.name-rules")
                    .stringType()
                    .defaultValue("DEFAULT")
                    .withDescription(
                            "Kerberos auth-to-local rules used to map authenticated principals to "
                                    + "local user names.");

    /** Validity of JobManager web authentication tokens. */
    public static final ConfigOption<Duration> AUTHENTICATION_TOKEN_VALIDITY =
            key("web.authentication.token.validity")
                    .durationType()
                    .defaultValue(Duration.ofHours(10))
                    .withDescription(
                            "Validity period for JobManager web SPNEGO authentication cookies.");

    /** Cookie path for JobManager web authentication tokens. */
    public static final ConfigOption<String> AUTHENTICATION_COOKIE_PATH =
            key("web.authentication.cookie.path")
                    .stringType()
                    .defaultValue("/")
                    .withDescription(
                            "Cookie path for JobManager web SPNEGO authentication cookies.");

    /** Shared signing secret for JobManager web authentication tokens. */
    public static final ConfigOption<String> AUTHENTICATION_SIGNATURE_SECRET =
            key("web.authentication.signature.secret")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Shared secret for signing JobManager web SPNEGO authentication "
                                    + "cookies. If neither this option nor the secret-file option "
                                    + "is set, a random process-local secret is generated. "
                                    + "Configure the same secret for all JobManager instances "
                                    + "that should accept each other's authentication cookies.");

    /** File containing the shared signing secret for JobManager web authentication tokens. */
    public static final ConfigOption<String> AUTHENTICATION_SIGNATURE_SECRET_FILE =
            key("web.authentication.signature.secret-file")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "File containing the shared secret for signing JobManager web SPNEGO "
                                    + "authentication cookies. Configure the same secret file for "
                                    + "all JobManager instances that should accept each other's "
                                    + "authentication cookies.");

    /** Config parameter defining the number of checkpoints to remember for recent history. */
    public static final ConfigOption<Integer> CHECKPOINTS_HISTORY_SIZE =
            key("web.checkpoints.history")
                    .intType()
                    .defaultValue(10)
                    .withDeprecatedKeys("jobmanager.web.checkpoints.history")
                    .withDescription("Number of checkpoints to remember for recent history.");

    /** The maximum number of failures kept in the exception history. */
    // the parameter is referenced in the UI and might need to be updated there as well
    @Documentation.Section(Documentation.Sections.ALL_JOB_MANAGER)
    public static final ConfigOption<Integer> MAX_EXCEPTION_HISTORY_SIZE =
            key("web.exception-history-size")
                    .intType()
                    .defaultValue(16)
                    .withDescription(
                            "The maximum number of failures collected by the exception history per job.");

    /** @deprecated - no longer used. */
    @Deprecated
    public static final ConfigOption<Integer> BACKPRESSURE_CLEANUP_INTERVAL =
            key("web.backpressure.cleanup-interval")
                    .intType()
                    .defaultValue(10 * 60 * 1000)
                    .withDeprecatedKeys("jobmanager.web.backpressure.cleanup-interval")
                    .withDescription("This config option is no longer used");

    /** @deprecated - no longer used. */
    @Deprecated
    public static final ConfigOption<Integer> BACKPRESSURE_REFRESH_INTERVAL =
            key("web.backpressure.refresh-interval")
                    .intType()
                    .defaultValue(60 * 1000)
                    .withDeprecatedKeys("jobmanager.web.backpressure.refresh-interval")
                    .withDescription("This config option is no longer used");

    /** @deprecated - no longer used. */
    @Deprecated
    public static final ConfigOption<Integer> BACKPRESSURE_NUM_SAMPLES =
            key("web.backpressure.num-samples")
                    .intType()
                    .defaultValue(100)
                    .withDeprecatedKeys("jobmanager.web.backpressure.num-samples")
                    .withDescription("This config option is no longer used");

    /** @deprecated - no longer used. */
    @Deprecated
    public static final ConfigOption<Integer> BACKPRESSURE_DELAY =
            key("web.backpressure.delay-between-samples")
                    .intType()
                    .defaultValue(50)
                    .withDeprecatedKeys("jobmanager.web.backpressure.delay-between-samples")
                    .withDescription("This config option is no longer used");

    /** Timeout for asynchronous operations by the web monitor in milliseconds. */
    public static final ConfigOption<Duration> TIMEOUT =
            key("web.timeout")
                    .durationType()
                    .defaultValue(Duration.ofMillis(10L * 60L * 1000L))
                    .withDescription("Timeout for asynchronous operations by the web monitor.");

    // ------------------------------------------------------------------------

    /** Not meant to be instantiated. */
    private WebOptions() {}

    /** Authentication types supported by the JobManager web-frontend. */
    public enum WebAuthenticationType {
        /** Authentication is disabled. */
        NONE,

        /** Kerberos/SPNEGO authentication. */
        KERBEROS
    }
}
