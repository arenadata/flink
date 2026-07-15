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

package org.apache.flink.runtime.webmonitor.security;

import org.apache.flink.util.ConfigurationException;

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.regex.Pattern;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** Kerberos/SPNEGO acceptor for the JobManager web endpoint. */
final class JobManagerSpnegoAuthenticator implements SpnegoAuthenticator {

    private static final Logger LOG = LoggerFactory.getLogger(JobManagerSpnegoAuthenticator.class);

    static final String AUTHENTICATION_SCHEME_NEGOTIATE = "Negotiate";
    static final String AUTHENTICATE_HEADER_NEGOTIATE = "Negotiate";

    private static final Pattern HTTP_PRINCIPAL_PATTERN = Pattern.compile("HTTP/.*");

    private final Subject serverSubject;
    private final GSSManager gssManager;

    private JobManagerSpnegoAuthenticator(Subject serverSubject, GSSManager gssManager) {
        this.serverSubject = checkNotNull(serverSubject);
        this.gssManager = checkNotNull(gssManager);
    }

    static JobManagerSpnegoAuthenticator create(JobManagerWebAuthenticationConfig config)
            throws ConfigurationException {
        File keytabFile = config.getKerberosKeytab().toFile();
        if (!keytabFile.isFile()) {
            throw new ConfigurationException(
                    "JobManager web authentication Kerberos keytab does not exist or is not a file: "
                            + config.getKerberosKeytab());
        }

        Subject serverSubject = new Subject();
        KeyTab keytab = KeyTab.getInstance(keytabFile);
        serverSubject.getPrivateCredentials().add(keytab);

        if ("*".equals(config.getKerberosPrincipal())) {
            addWildcardHttpPrincipals(serverSubject, config.getKerberosKeytab().toString());
        } else {
            addPrincipal(
                    serverSubject,
                    keytab,
                    config.getKerberosPrincipal(),
                    config.getKerberosKeytab().toString());
        }

        configureKerberosNameRules(config);

        GSSManager gssManager;
        try {
            gssManager =
                    Subject.doAs(
                            serverSubject,
                            (PrivilegedExceptionAction<GSSManager>) GSSManager::getInstance);
        } catch (PrivilegedActionException e) {
            throw new ConfigurationException(
                    "Could not initialize JobManager web SPNEGO acceptor.", e.getException());
        }

        return new JobManagerSpnegoAuthenticator(serverSubject, gssManager);
    }

    @Override
    public JobManagerSpnegoAuthenticationResult authenticate(String authorizationHeader)
            throws AuthenticationException {
        if (!hasNegotiateScheme(authorizationHeader)) {
            return JobManagerSpnegoAuthenticationResult.challenge(AUTHENTICATE_HEADER_NEGOTIATE);
        }

        String encodedClientToken =
                authorizationHeader.substring(AUTHENTICATION_SCHEME_NEGOTIATE.length()).trim();
        if (encodedClientToken.isEmpty()) {
            throw new AuthenticationException("Missing SPNEGO token.");
        }

        byte[] clientToken;
        try {
            clientToken = Base64.getDecoder().decode(encodedClientToken);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationException("Invalid SPNEGO token encoding.", e);
        }

        try {
            String serverPrincipal = KerberosUtil.getTokenServerName(clientToken);
            if (!serverPrincipal.startsWith("HTTP/")) {
                throw new AuthenticationException(
                        "Invalid SPNEGO server principal in client token.");
            }
            return Subject.doAs(
                    serverSubject,
                    (PrivilegedExceptionAction<JobManagerSpnegoAuthenticationResult>)
                            () -> runWithPrincipal(serverPrincipal, clientToken));
        } catch (PrivilegedActionException e) {
            Throwable cause = e.getException();
            if (cause instanceof AuthenticationException) {
                throw (AuthenticationException) cause;
            }
            throw new AuthenticationException(cause);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationException(e);
        }
    }

    private JobManagerSpnegoAuthenticationResult runWithPrincipal(
            String serverPrincipal, byte[] clientToken) throws GSSException, IOException {
        GSSContext gssContext = null;
        GSSCredential gssCredential = null;
        try {
            LOG.trace(
                    "Starting JobManager web SPNEGO step for server principal {}.",
                    serverPrincipal);
            gssCredential =
                    gssManager.createCredential(
                            gssManager.createName(
                                    serverPrincipal, KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID),
                            GSSCredential.INDEFINITE_LIFETIME,
                            new Oid[] {
                                KerberosUtil.GSS_SPNEGO_MECH_OID, KerberosUtil.GSS_KRB5_MECH_OID
                            },
                            GSSCredential.ACCEPT_ONLY);
            gssContext = gssManager.createContext(gssCredential);
            byte[] serverToken = gssContext.acceptSecContext(clientToken, 0, clientToken.length);
            String authenticateHeader = createAuthenticateHeader(serverToken);

            if (!gssContext.isEstablished()) {
                LOG.trace("JobManager web SPNEGO step is not complete yet.");
                return JobManagerSpnegoAuthenticationResult.challenge(
                        authenticateHeader == null
                                ? AUTHENTICATE_HEADER_NEGOTIATE
                                : authenticateHeader);
            }

            String clientPrincipal = gssContext.getSrcName().toString();
            String userName = new KerberosName(clientPrincipal).getShortName();
            AuthenticationToken token =
                    new AuthenticationToken(
                            userName,
                            clientPrincipal,
                            JobManagerAuthenticationTokenSigner.TOKEN_TYPE_KERBEROS);
            LOG.trace("JobManager web SPNEGO completed for client principal {}.", clientPrincipal);
            return JobManagerSpnegoAuthenticationResult.authenticated(token, authenticateHeader);
        } finally {
            if (gssContext != null) {
                gssContext.dispose();
            }
            if (gssCredential != null) {
                gssCredential.dispose();
            }
        }
    }

    @Nullable
    private static String createAuthenticateHeader(byte[] serverToken) {
        if (serverToken == null || serverToken.length == 0) {
            return null;
        }
        return AUTHENTICATE_HEADER_NEGOTIATE
                + " "
                + Base64.getEncoder().encodeToString(serverToken);
    }

    private static boolean hasNegotiateScheme(String authorizationHeader) {
        return authorizationHeader != null
                && authorizationHeader.length() >= AUTHENTICATION_SCHEME_NEGOTIATE.length()
                && authorizationHeader.regionMatches(
                        true,
                        0,
                        AUTHENTICATION_SCHEME_NEGOTIATE,
                        0,
                        AUTHENTICATION_SCHEME_NEGOTIATE.length())
                && (authorizationHeader.length() == AUTHENTICATION_SCHEME_NEGOTIATE.length()
                        || Character.isWhitespace(
                                authorizationHeader.charAt(
                                        AUTHENTICATION_SCHEME_NEGOTIATE.length())));
    }

    private static void addWildcardHttpPrincipals(Subject serverSubject, String keytab)
            throws ConfigurationException {
        String[] principals;
        try {
            principals = KerberosUtil.getPrincipalNames(keytab, HTTP_PRINCIPAL_PATTERN);
        } catch (IOException e) {
            throw new ConfigurationException(
                    "Could not read JobManager web authentication Kerberos keytab.", e);
        }
        if (principals.length == 0) {
            throw new ConfigurationException(
                    "JobManager web authentication Kerberos keytab does not contain any HTTP principals.");
        }
        for (String principal : principals) {
            addPrincipal(serverSubject, null, principal, keytab);
        }
    }

    private static void addPrincipal(
            Subject serverSubject, KeyTab keytab, String principal, String keytabPath)
            throws ConfigurationException {
        try {
            Principal kerberosPrincipal = new KerberosPrincipal(principal);
            if (keytab != null) {
                KerberosKey[] keys = keytab.getKeys((KerberosPrincipal) kerberosPrincipal);
                if (keys.length == 0) {
                    throw new ConfigurationException(
                            String.format(
                                    "JobManager web authentication Kerberos keytab '%s' does not contain principal '%s'.",
                                    keytabPath, principal));
                }
                for (KerberosKey key : keys) {
                    key.destroy();
                }
            }
            serverSubject.getPrincipals().add(kerberosPrincipal);
            LOG.info(
                    "Using JobManager web SPNEGO keytab {} for principal {}.",
                    keytabPath,
                    principal);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "Invalid JobManager web authentication Kerberos principal: " + principal, e);
        } catch (javax.security.auth.DestroyFailedException e) {
            throw new ConfigurationException(
                    "Could not validate JobManager web authentication Kerberos keytab.", e);
        }
    }

    private static void configureKerberosNameRules(JobManagerWebAuthenticationConfig config)
            throws ConfigurationException {
        try {
            KerberosName.setRules(config.getKerberosNameRules());
            KerberosName.setRuleMechanism(KerberosName.DEFAULT_MECHANISM);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "Invalid JobManager web SPNEGO Kerberos name rules.", e);
        }
    }
}
