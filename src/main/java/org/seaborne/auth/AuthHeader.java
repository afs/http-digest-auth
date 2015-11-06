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

import java.util.Map ;
import java.util.Objects ;

/** Parsed "Authentication" header for digect authentication. */
public class AuthHeader {
    // Lowercased names.
    public static String strDigest   = "digest";
    public static String strUsername = "username";
    public static String strRealm    = "realm";
    public static String strNonce    = "nonce";
    public static String strNc       = "nc";
    public static String strCNonce   = "cnonce";
    public static String strQop      = "qop";
    public static String strResponse = "response";
    public static String strOpaque   = "opaque" ;
    public static String strUri      = "uri";
    
    public final String realm ;
    public final String nonce ;
    public final String method ;
    public final String uri ;
    public final String response ;
    public final String opaque ;
    public final String qop ;
    public final String nc ;
    public final String cnonce ;
    public final String username ;
    public final Map<String, String> parsed ;
     
    // Always created by parsing the string.
    private AuthHeader(String username, String realm, String nonce, String method, String uri, String response, String opaque,
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
        this.parsed = parsed ;
    }

    /** Parse "Authentication:" */ 
    static public AuthHeader parse(String authHeaderStr, String methodStr) {
        Map<String, String> authHeader = null ;
        try {
            authHeader = AuthStringTokenizer.parse(authHeaderStr) ;
        } catch (Throwable ex) {
            return null ;
        }
        
        try {
            return new AuthHeader(nonNull(strUsername, authHeader.get(strUsername)),
                                  nonNull(strRealm, authHeader.get(strRealm)),
                                  nonNull(strNonce, authHeader.get(strNonce)),
                                  methodStr, 
                                  authHeader.get(strUri),
                                  nonNull(strResponse, authHeader.get(strResponse)),
                                  nonNull(strOpaque, authHeader.get(strOpaque)),
                                  authHeader.get(strQop),
                                  authHeader.get(strNc),
                                  authHeader.get(strCNonce),
                                  authHeader) ;
        } catch (NullPointerException ex) {
            return null ;
        }
    }
    
    private static String nonNull(String field, String s) {
        return Objects.requireNonNull(s, "Field="+field) ;
    }
    

}