/**
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

/** Parsed "Authentication" header for digest authentication. */
public class AuthResponseHeader {
    public final String realm;
    public final String nonce;
    public final String method;
    public final String uri;
    public final String response;
    public final String opaque;
    public final String qop;
    public final String nc;
    public final String cnonce;
    public final String username;
    public final Map<String, String> parsed;
     
    /** Parse "WWW-Authenticate:" challenge message */ 
    static public AuthResponseHeader parseChallenge(String authHeaderStr, String methodStr) {
        Map<String, String> authHeader = null;
        try {
            authHeader = AuthStringTokenizer.parse(authHeaderStr);
        } catch (Throwable ex) {
            return null;
        }
        try {
            return new AuthResponseHeader(null, //nonNull(strUsername, authHeader.get(strUsername)),
                                  nonNull(AuthHeader.strRealm, authHeader.get(AuthHeader.strRealm)),
                                  nonNull(AuthHeader.strNonce, authHeader.get(AuthHeader.strNonce)),
                                  methodStr, 
                                  authHeader.get(AuthHeader.strUri),
                                  null, //nonNull(strResponse, authHeader.get(strResponse)),
                                  nonNull(AuthHeader.strOpaque, authHeader.get(AuthHeader.strOpaque)),
                                  authHeader.get(AuthHeader.strQop),
                                  authHeader.get(AuthHeader.strNc),
                                  authHeader.get(AuthHeader.strCNonce),
                                  authHeader);
        } catch (NullPointerException ex) {
            return null;
        }
    }

    /** Parse "Authentication:" */ 
    static public AuthResponseHeader parse(String authHeaderStr, String methodStr) {
        Map<String, String> authHeader = null;
        try {
            authHeader = AuthStringTokenizer.parse(authHeaderStr);
        } catch (Throwable ex) {
            return null;
        }
        
        try {
            return new AuthResponseHeader(nonNull(AuthHeader.strUsername, authHeader.get(AuthHeader.strUsername)),
                                  nonNull(AuthHeader.strRealm, authHeader.get(AuthHeader.strRealm)),
                                  nonNull(AuthHeader.strNonce, authHeader.get(AuthHeader.strNonce)),
                                  methodStr, 
                                  authHeader.get(AuthHeader.strUri),
                                  nonNull(AuthHeader.strResponse, authHeader.get(AuthHeader.strResponse)),
                                  nonNull(AuthHeader.strOpaque, authHeader.get(AuthHeader.strOpaque)),
                                  authHeader.get(AuthHeader.strQop),
                                  authHeader.get(AuthHeader.strNc),
                                  authHeader.get(AuthHeader.strCNonce),
                                  authHeader);
        } catch (NullPointerException ex) {
            return null;
        }
    }

    private AuthResponseHeader(String username, String realm, String nonce, String method, String uri, String response, String opaque,
                      String qop, String nc, String cnonce,
                      Map<String, String> parsed) {
        super();
        this.username = username;
        this.realm = realm;
        this.nonce = nonce;
        this.method = method;
        this.uri = uri;
        this.response = response;
        this.opaque = opaque;
        this.qop = qop;
        this.nc = nc;
        this.cnonce = cnonce;
        this.parsed = parsed;
    }


    private static String nonNull(String field, String s) {
        return Objects.requireNonNull(s, "Field="+field);
    }
    

}