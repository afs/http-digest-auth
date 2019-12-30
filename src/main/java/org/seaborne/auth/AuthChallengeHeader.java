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

package org.seaborne.auth;

import java.util.Map;
import java.util.Objects;

public class AuthChallengeHeader {
    public final String realm;
    public final String nonce;
    public final String method;
    public final String uri;
    public final String opaque;
    public final String qop;
    public final Map<String, String> parsed;
    
    // Wikipedia example.
//        WWW-Authenticate: Digest realm="testrealm@host.com",
//                             qop="auth,auth-int",
//                             nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
//                             opaque="5ccc069c403ebaf9f0171e9517f40e41"
     
    /** Parse "WWW-Authenticate:" challenge message */ 
    static public AuthChallengeHeader parse(String authHeaderStr, String uri, String methodStr) {
        Map<String, String> authHeader = null;
        try {
            authHeader = AuthStringTokenizer.parse(authHeaderStr);
        } catch (Throwable ex) {
            return null;
        }
        try {
            return new AuthChallengeHeader(
                                  nonNull(AuthHeader.strRealm, authHeader.get(AuthHeader.strRealm)),
                                  nonNull(AuthHeader.strNonce, authHeader.get(AuthHeader.strNonce)),
                                  methodStr,
                                  uri,
                                  nonNull(AuthHeader.strOpaque, authHeader.get(AuthHeader.strOpaque)),
                                  authHeader.get(AuthHeader.strQop),
                                  authHeader);
        } catch (NullPointerException ex) {
            return null;
        }
    }
    
    private AuthChallengeHeader(String realm, String nonce, String method, String uri, String opaque, String qop, Map<String, String> parsed) {
                 super();
                 this.realm = realm;
                 this.nonce = nonce;
                 this.method = method;
                 this.uri = uri;
                 this.opaque = opaque;
                 this.qop = qop;
                 this.parsed = parsed;
                 }

    private static String nonNull(String field, String s) {
        return Objects.requireNonNull(s, "Field="+field);
    }
}
