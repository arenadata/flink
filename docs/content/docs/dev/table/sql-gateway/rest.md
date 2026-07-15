---
title: REST Endpoint
weight: 2
type: docs
aliases:
- /dev/table/sql-gateway/rest.html
---
<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# REST Endpoint

The REST endpoint allows user to connect to SQL Gateway with REST API.

Overview of SQL Processing
----------------

### Open Session

When the client connects to the SQL Gateway, the SQL Gateway creates a `Session` as the context to store the users-specified information 
during the interactions between the client and SQL Gateway. After the creation of the `Session`, the SQL Gateway server returns an identifier named
`SessionHandle` for later interactions.

### Submit SQL

After the registration of the `Session`, the client can submit the SQL to the SQL Gateway server. When submitting the SQL,
the SQL is translated to an `Operation` and an identifier named `OperationHandle` is returned for fetch results later. The Operation has
its lifecycle, the client is able to cancel the execution of the `Operation` or close the `Operation` to release the resources used by the `Operation`.

### Fetch Results

With the `OperationHandle`, the client can fetch the results from the `Operation`. If the `Operation` is ready, the SQL Gateway will return a batch 
of the data with the corresponding schema and a URI that is used to fetch the next batch of the data. When all results have been fetched, the 
SQL Gateway will fill the `resultType` in the response with value `EOS` and the URI to the next batch of the data is null.

{{< img width="100%" src="/fig/sql-gateway-interactions.png" alt="SQL Gateway Interactions" >}}

Endpoint Options
----------------

<table class="table table-bordered">
    <thead>
        <tr>
            <th class="text-left" style="width: 20%">Key</th>
            <th class="text-left" style="width: 15%">Default</th>
            <th class="text-left" style="width: 10%">Type</th>
            <th class="text-left" style="width: 55%">Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.address</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>The address that should be used by clients to connect to the sql gateway server.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.bind-address</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>The address that the sql gateway server binds itself.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.bind-port</h5></td>
            <td style="word-wrap: break-word;">"8083"</td>
            <td>String</td>
            <td>The port that the sql gateway server binds itself. Accepts a list of ports (“50100,50101”), ranges (“50100-50200”) or a combination of both. It is recommended to set a range of ports to avoid collisions when multiple sql gateway servers are running on the same machine.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.port</h5></td>
            <td style="word-wrap: break-word;">8083</td>
            <td>Integer</td>
            <td>The port that the client connects to. If bind-port has not been specified, then the sql gateway server will bind to this port.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.type</h5></td>
            <td style="word-wrap: break-word;">NONE</td>
            <td>Enum</td>
            <td>Authentication type for the SQL Gateway REST endpoint. Supported values are NONE and KERBEROS.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.kerberos.principal</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>Kerberos principal for accepting SPNEGO requests when REST authentication type is KERBEROS. The value supports HTTP/_HOST@REALM host replacement and * to load all HTTP principals from the keytab.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.kerberos.keytab</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>Path to the keytab containing the REST SPNEGO service principal. This option is required when REST authentication type is KERBEROS.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.kerberos.name-rules</h5></td>
            <td style="word-wrap: break-word;">DEFAULT</td>
            <td>String</td>
            <td>Kerberos auth-to-local rules used to map the authenticated Kerberos principal to a local user name.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.token.validity</h5></td>
            <td style="word-wrap: break-word;">10 h</td>
            <td>Duration</td>
            <td>Validity of the signed REST authentication cookie issued after a successful SPNEGO exchange.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.cookie.path</h5></td>
            <td style="word-wrap: break-word;">/</td>
            <td>String</td>
            <td>Path attribute for the REST authentication cookie.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.signature.secret</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>Shared secret used to sign REST authentication cookies. If neither this option nor signature.secret-file is configured, a random process-local secret is generated.</td>
        </tr>
        <tr>
            <td><h5>sql-gateway.endpoint.rest.authentication.signature.secret-file</h5></td>
            <td style="word-wrap: break-word;">(none)</td>
            <td>String</td>
            <td>Path to a file containing the shared secret used to sign REST authentication cookies. Configure either signature.secret or signature.secret-file, but not both.</td>
        </tr>
    </tbody>
</table>

REST SPNEGO Authentication
----------------

By default, the REST endpoint does not authenticate requests. If the endpoint is reachable from an untrusted network, any client that can connect to it can create sessions, execute SQL, submit jobs, and access configured data sources. Bind the endpoint to a trusted interface, place it behind an authenticated gateway, or enable SPNEGO authentication before exposing it beyond a trusted boundary.

SPNEGO authentication is opt-in and applies to every SQL Gateway REST path, including `/v*/info`.

```yaml
sql-gateway.endpoint.rest.authentication.type: KERBEROS
sql-gateway.endpoint.rest.authentication.kerberos.principal: HTTP/_HOST@EXAMPLE.COM
sql-gateway.endpoint.rest.authentication.kerberos.keytab: /etc/security/keytabs/flink-sql-gateway.keytab
sql-gateway.endpoint.rest.authentication.kerberos.name-rules: DEFAULT
sql-gateway.endpoint.rest.authentication.signature.secret-file: /etc/flink/sql-gateway-cookie-secret
```

Clients must use an HTTP client that can negotiate SPNEGO, for example:

```bash
$ kinit user@EXAMPLE.COM
$ curl --negotiate -u : http://sql-gateway-host:8083/v1/info
$ curl --negotiate -u : --request POST http://sql-gateway-host:8083/v1/sessions
```

Unauthenticated requests receive `401` with `WWW-Authenticate: Negotiate`. Malformed or invalid SPNEGO tokens receive `403`.
After a successful SPNEGO exchange, the REST endpoint issues a signed `hadoop.auth` cookie. Multi-instance or load-balanced SQL Gateway deployments must configure the same `sql-gateway.endpoint.rest.authentication.signature.secret` or `sql-gateway.endpoint.rest.authentication.signature.secret-file` on every instance; otherwise cookies issued by one instance will not be accepted by another.

The built-in Flink SQL Client and Flink JDBC Driver do not negotiate SPNEGO with the SQL Gateway REST endpoint in this change. Use an HTTP SPNEGO-capable client or put the SQL Gateway behind a separate authenticated gateway or proxy when those clients are required.

REST API
----------------

The available OpenAPI specification is as follows. The default version is v3.

| Version                                                                             | Description                                                  |
|-------------------------------------------------------------------------------------|--------------------------------------------------------------|
| [Open API v1 specification]({{< ref_static "generated/rest_v1_sql_gateway.yml" >}}) | Allow users to submit statements to the gateway and execute. |
| [Open API v2 specification]({{< ref_static "generated/rest_v2_sql_gateway.yml" >}}) | Supports SQL Client to connect to the gateway.               |
| [Open API v3 specification]({{< ref_static "generated/rest_v3_sql_gateway.yml" >}}) | Supports Materialized Table refresh operation.               |
| [Open API v4 specification]({{< ref_static "generated/rest_v4_sql_gateway.yml" >}}) | Supports to deploy script in application mode.               |

{{< hint warning >}}
The OpenAPI specification is still experimental.
{{< /hint >}}

#### API reference

{{< tabs "f00ed142-b05f-44f0-bafc-799080c1d40d" >}}
{{< tab "v4" >}}

{{< generated/rest_v4_sql_gateway >}}

{{< /tab >}}
{{< tab "v3" >}}

{{< generated/rest_v3_sql_gateway >}}

{{< /tab >}}
{{< tab "v2" >}}

{{< generated/rest_v2_sql_gateway >}}

{{< /tab >}}
{{< tab "v1" >}}

{{< generated/rest_v1_sql_gateway >}}

{{< /tab >}}
{{< /tabs >}}

Data Type Mapping
----------------

Currently, REST endpoint supports to serialize the `RowData` with query parameter `rowFormat`. REST endpoint uses JSON format to serialize 
the Table Objects. Please refer [JSON format]({{< ref "docs/connectors/table/formats/json#data-type-mapping" >}}) to the mappings. 

REST endpoint also supports to serialize the `RowData` with `PLAIN_TEXT` format that automatically cast all columns to the `String`.

{{< top >}}
