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

import static org.seaborne.auth.RFC2617.A1_MD5 ;
import static org.seaborne.auth.RFC2617.* ;

import java.io.IOException ;
import java.util.Map ;
import java.util.Objects ;
import java.util.UUID ;
import java.util.concurrent.ConcurrentHashMap ;

import javax.servlet.ServletContext ;
import javax.servlet.http.HttpServletRequest ;
import javax.servlet.http.HttpServletResponse ;

import org.apache.commons.lang3.StringUtils ;
import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

/** Core engine for Digest Authetication (<a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>).
 * <p>
 * This implementation is a 'clean room' Java implementation of Digest HTTP Authentication specification per
 * <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>.
 * <p>
 * Digest authentication functions as follows:
 * <ol>
 * <li>A request comes in for a resource that requires authentication and authorization.</li>
 * <li>The server replies with a 401 response status, sets the <code>WWW-Authenticate</code> header,
 *  with a opaque string (to identify this session),   
 * <li>Upon receiving this <code>WWW-Authenticate</code> challenge from the server, the client then takes a
 * username and a password and calculates the response.
 * <li>The client then sends another request for the same resource with the following header:<br/>
 * <p><code>Authorization: Digest <em>...</em></code></p></li>
 * </ol>
 * The advantage over basic authentication is that the password does not go over the network
 * in a way that an evesdropper can recover.  It is combined with other information and hashed
 * with MD5 or other comparable non-reversible hash function. (Only MD5 supported here.)
 * <p>
 * This class does not concern itself with how the password is obtained. 
 * See operation {@link #getPassword(ServletContext, String)}.     
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>
 * @see <a href="https://en.wikipedia.org/wiki/Digest_access_authentication">Wikipedia: Digest Access Authentication</a>
 */

public class DigestHttp {
    /** Log on a provided logger. */
    private final Logger log ;

    /** HTTP Authorization header, equal to <code>Authorization</code> */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

    /** HTTP Authentication header, equal to <code>WWW-Authenticate</code> */
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /** The name of the scheme */ 
    private static String DIGEST_AUTH = HttpServletRequest.DIGEST_AUTH ;

    // XXX Concurrency.
    
    // Map from the opaque to valid credentials.
    private Map<String, DigestSession> activeSessions = new ConcurrentHashMap<>() ;

    // The incomplete credentials are registered when the challenge is made.
    // These are moved to the  activeSessions when first sucessfully used.
    private Map<String, DigestSession> pendingSessions = new ConcurrentHashMap<>() ;

    private final String realm ;

    private final PasswordGetter passwordGetter; 
    /** Create a HTTP digest authentication engine : subclass must implement
     * {@link #getPassword} and {@link #getRealm}   
     */
    protected DigestHttp(Logger log, PasswordGetter pwGetter) {
        this(log, null, pwGetter) ;
    }

    protected DigestHttp(PasswordGetter pwGetter) {
        this(LoggerFactory.getLogger(DigestHttp.class), null, pwGetter) ;
    }

    /** Create a HTTP digest authentication engine : subclass must implement
     * {@link #getPassword} and {@link #getRealm}   
     */
    public DigestHttp(Logger log, String realm, PasswordGetter pwGetter) {
        Objects.requireNonNull(log) ;
        Objects.requireNonNull(pwGetter) ;
        this.realm = realm ;
        this.passwordGetter = pwGetter ;
        this.log = log ;
    }
    
    /** The RFC 2617 algorithm for determing whether a request is acceptable or not.
     * See also {@link #sendChallenge(HttpServletRequest, HttpServletResponse)}.
     * @return <code>true</code> if accepable, else <code>false</code>.
     */
    public boolean accessYesOrNo(HttpServletRequest request, HttpServletResponse response) {
        String x = getAuthzHeader(request) ;
        if ( x == null ) {
            if ( log.isDebugEnabled() )
                log.debug("accessYesOrNo: null header");
            return false ;
        }
        if ( log.isDebugEnabled() )
            log.debug("accessYesOrNo: "+x);
        
        ServletContext servletContext = request.getServletContext() ;
        
        AuthHeader authHeader = AuthHeader.parse(x, request.getMethod()) ;
        if ( authHeader == null ) {
            if ( log.isDebugEnabled() )
                log.debug("accessYesOrNo: Bad auth header");
            return false ;
        }
        
        if ( ! authHeader.parsed.containsKey(AuthHeader.strDigest) )
            badRequest(request, response, "No 'Digest' in Authorization header") ;
        
        if ( authHeader.opaque == null ) {
            if ( log.isDebugEnabled() )
                log.debug("accessYesOrNo: Bad Authorization header") ;
            badRequest(request, response, "Bad Authorization header") ;
            return false ;
        }
        
        // XXX CONCURRENECY 
        
        String opaque = authHeader.opaque ;
        
        DigestSession digestSession = null ;
        
        if ( activeSessions.containsKey(opaque) ) {
            digestSession = activeSessions.get(opaque) ;
        } else if ( pendingSessions.containsKey(opaque) ) {
            // This might be null due to another request
            // but we check below for null.
            digestSession = pendingSessions.remove(opaque) ;
        }
         
        if ( digestSession == null ) {
            if ( log.isDebugEnabled() )
                log.debug("accessYesOrNo: No opaque");
            return false ; 
        }
        
        String requestUri = request.getRequestURI() ;
        String requestMethod = request.getMethod() ;
        String username = authHeader.username ;
        
        // Some checks.
        // XXX Check in RFC
        if ( ! digestSession.username.isEmpty() && ! digestSession.username.equals(authHeader.username) ) {
            if ( log.isDebugEnabled() )
                log.debug("Username change: header="+authHeader.username+" : expected"+ digestSession.username) ;  
            badRequest(request, response, "Different username in 'Authorization' header") ;
        }
        if ( ! digestSession.realm.equals(authHeader.realm) ) {
            if ( log.isDebugEnabled() )
                log.debug("Realm change: header="+authHeader.realm+" : expected"+ digestSession.realm) ;  
            badRequest(request, response, "Different realm in 'Authorization' header") ;
        }
        if ( ! requestUri.equals(authHeader.uri) ) {
            if ( log.isDebugEnabled() )
                log.debug("URI change: header="+authHeader.uri+" : expected"+ requestUri) ;  
            badRequest(request, response, "Different URI in 'Authorization' header") ;
        }
        if ( ! requestMethod.equals(authHeader.method) ) {
            if ( log.isDebugEnabled() )
                log.debug("Method change: header="+authHeader.method+" : expected"+ requestMethod) ;  
            badRequest(request, response, "Different HTTP method in 'Authorization' header") ;
        }
        
        // Check nonce.
//        log("Server nonce = "+perm.nonce);
//        log("Header nonce = "+ah.nonce);

        String password = getPassword(servletContext, username) ;
        
        if ( log.isDebugEnabled() )
            //log.debug("Attempt: User = " + username + " : Password = " + password);
            log.debug("Attempt: User = " + username);
        
        String digestCalc = calcDigest(authHeader, password) ;
        String digestRequest = authHeader.response ;
        
        if ( ! digestCalc.equals(digestRequest) ) {
            // Remove all.
            pendingSessions.remove(opaque) ;
            activeSessions.remove(opaque) ;
            if ( log.isDebugEnabled() )
                log.debug("Digest does not match");
            return false ; 
        }
        
        boolean challengeResponse = StringUtils.isEmpty(digestSession.username) ; 
        if ( challengeResponse ) {
            // First time - complete digestSession details.
            digestSession.username = username ;
            activeSessions.put(opaque, digestSession) ;
        }

        if ( log.isDebugEnabled() ) { 
            //log.debug("request: "+httpRequest.getRequestURI());
            log.debug("User "+digestSession.username+" authorized") ;
        }
        return true ;
    }

    /** Return the session credentials keyed by {@code opaque}.
     * This is valid only after the first response to a challenga has been validated.
     * It does not return partial credentials. 
     * @param opaque
     * @return DigestSession
     */
    public DigestSession getCredentials(String opaque) {
        return activeSessions.get(opaque) ;
    }
    
    protected String getPassword(ServletContext servletContext, String username) {
        return passwordGetter.getPassword(servletContext, username) ;
    }

    private String getRealm() {
        return realm ;
    }
    
    /** The RFC 2617 challenge response */
    public void sendChallenge(HttpServletRequest request, HttpServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Sending 401 authentication challenge response.");
        }
        String newNonce = genString() ;
        String newOpaque = genString() ;
        
        // This is what we are expecting.
        // No user or passord at this point.
        DigestSession perm = new DigestSession(newOpaque, getRealm(), request.getMethod(), request.getRequestURI(), newNonce) ;
        pendingSessions.put(newOpaque, perm) ;
        
        String x = "Digest realm="+perm.realm
            +       " , qop=\"auth\""
            +       " , nonce=\""+perm.nonce+"\""
            +       " , opaque=\""+perm.opaque+"\""
            ;
        if ( log.isDebugEnabled() )
            log.debug("Challenge: "+x);
        
        response.setHeader(AUTHENTICATE_HEADER, x) ;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /** From the digest header, and the expected credentials,
     * calculate the string expected in the "response" field of the
     * "Authorization" header.
     * Method and URI are taken from the AuthHeader   
     */
    private static String calcDigest(AuthHeader auth, String password) {
        String a1 = A1_MD5(auth.username, auth.realm, password) ;
        if ( auth.qop == null ) {
            // RFC 2069
            // Firefox seems to prefer this form??
            return KD(H(a1), auth.nonce+":"+H(A2_auth(auth.method, auth.uri))) ;
        }
        else {
            Objects.nonNull(auth.cnonce) ;
            Objects.nonNull(auth.nc) ;
            return KD(H(a1),
                      auth.nonce+":"+auth.nc+":"+auth.cnonce+":"+auth.qop+":"+H(A2_auth(auth.method, auth.uri))
                    ) ;
        }
    }
        
    /**
     * Returns the {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the specified HttpServletRequest.
     */
    private String getAuthzHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION_HEADER);
    }

    // Generate unguessable hex strings 
    private static String genString() { return  UUID.randomUUID().toString().replaceAll("-",  "") ; }

    private void badRequest(HttpServletRequest request, HttpServletResponse response, String message) {
        try { response.sendError(HttpServletResponse.SC_BAD_REQUEST, message); }
        catch (IOException e) { 
            log.warn("Exception on sending 400: "+e.getMessage());
        }
    }
}
