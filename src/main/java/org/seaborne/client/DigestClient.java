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

package org.seaborne.client;

import org.seaborne.auth.AuthChallengeHeader;
import org.seaborne.auth.DigestHttp;

public class DigestClient {
    public static void main(String ... args) {
//        WWW-Authenticate: Digest realm="testrealm@host.com",
//            qop="auth,auth-int",
//            nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
//            opaque="5ccc069c403ebaf9f0171e9517f40e41"
        
//        GET /dir/index.html HTTP/1.0
//        Host: localhost
//        Authorization: Digest username="Mufasa",
//                             realm="testrealm@host.com",
//                             nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
//                             uri="/dir/index.html",
//                             qop=auth,
//                             nc=00000001,
//                             cnonce="0a4f113b",
//                             response="6629fae49393a05397450978507c4ef1",
//                             opaque="5ccc069c403ebaf9f0171e9517f40e41"

        
// User: "Mufasa", password "Circle Of Life"
        
        // **** DigestHttp
        
        // Example challenge header.
        // No username, no response, choice of qop.
        // No URI, no method.
        String header = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\","+
                        " nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","+
                        " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        
        // Parse
        AuthChallengeHeader h = AuthChallengeHeader.parse(header, "/dir/index.html", "GET");
            
        String uri = "/dir/index.html";
        String method = "GET";
        
//        String realm = "testrealm@host.com";
//        String opaque = "5ccc069c403ebaf9f0171e9517f40e41";
        
        String nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
        String cnonce = "0a4f113b";
//        String algorithm = "MD5";
//        // If an algorithm is not specified, default to MD5.
//        if (algorithm == null) {
//            algorithm = "MD5";
//        }
        
        // requesy count (hexadecimal)
        String nc = "00000001";
        
        String username = "Mufasa";
        String password = "Circle Of Life";

//        // Calculation
//      HA1 = MD5( "Mufasa:testrealm@host.com:Circle Of Life" )
//      = 939e7578ed9e3c518a452acee763bce9
//
//  HA2 = MD5( "GET:/dir/index.html" )
//      = 39aff3a2bab6126f332b942af96d3366
//
//  Response = MD5( "939e7578ed9e3c518a452acee763bce9:\
//                   dcd98b7102dd2f0e8b11d0f600bfb0c093:\
//                   00000001:0a4f113b:auth:\
//                   39aff3a2bab6126f332b942af96d3366" )
//           = 6629fae49393a05397450978507c4ef1
// 
//        String HA1 = H(A1_MD5(username, h.realm, password));
//        System.out.println("HA1 = "+HA1);
//        
//        String HA2 = H(A2_auth(h.method, uri));
//        System.out.println("HA2 = "+HA2);
//        
//        String response = H( HA1+":"+h.nonce+":"+nc+":"+cnonce+":"+"auth"+":"+HA2);
//        System.out.println("response = "+response);
        
        
        String responseField = DigestHttp.calcDigestChallengeResponse(h, username, password, cnonce, nc, "auth");
        System.out.println("Response = "+responseField);
        System.out.println("Correct  = 6629fae49393a05397450978507c4ef1");
            
    }
}
