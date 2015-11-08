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

/** Session details */
public class DigestSession {
    public final String opaque ;
    public String username ;
    public final String realm ;
    // XXX remove? Used only for the challenge response -> ??
    public String method ;
    // XXX remove
    public String uri ;
    public final String nonce;
    
    public DigestSession(String opaque, String realm, String method, String uri, String nonce) {
        this(opaque, "", realm, method, uri, nonce) ;
    }
    
    public DigestSession(DigestSession other) {
        this(other.opaque, other.username, other.realm, other.method, other.uri, other.nonce) ;
    }
    
    public DigestSession(String opaque, String username, String realm, String method, String uri, String nonce) {
        this.opaque = opaque;
        this.username = username;
        this.realm = realm;
        this.method = method;
        this.uri = uri;
        this.nonce = nonce;
    }
}