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

package org.seaborne.auth.shiro;

import java.util.Locale ;

import javax.servlet.ServletContext ;
import javax.servlet.ServletRequest ;
import javax.servlet.ServletResponse ;
import javax.servlet.http.HttpServletRequest ;
import javax.servlet.http.HttpServletResponse ;

import org.apache.shiro.authc.AuthenticationException ;
import org.apache.shiro.authc.AuthenticationToken ;
import org.apache.shiro.subject.Subject ;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter ;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter ;
import org.apache.shiro.web.util.WebUtils ;
import org.seaborne.auth.AuthHeader ;
import org.seaborne.auth.DigestAuthenticationToken ;
import org.seaborne.auth.DigestHttp ;
import org.seaborne.auth.DigestSession ;
import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

/** Perform HTTP Digest authentication (RFC 2617).
 * <p>
 * The actual algorithm is in {@link DigestHttp} and this class is an adapter for the 
 * <a href="https://shiro.apache.org/">Apache Shiro fraemwork</a>. 
 *
 * @see DigestHttp
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @see <a href="https://en.wikipedia.org/wiki/Digest_access_authentication">Digest Access Authentication</a>
 * @see BasicHttpAuthenticationFilter
 * 
 * @since
 */
public abstract class DigestHttpAuthenticationFilter extends AuthenticatingFilter {
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);

    /** HTTP Authorization header, equal to <code>Authorization</code> */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

    /** HTTP Authentication header, equal to <code>WWW-Authenticate</code> */
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /** The name of the scheme */ 
    private static String DIGEST_AUTH = HttpServletRequest.DIGEST_AUTH ;

    private final DigestHttp engine;


    protected DigestHttpAuthenticationFilter() {
        this.engine = new DigestHttp(log, "Login", this::getPassword) ; 
    }
    
    /**
     * Determines whether the current subject should be allowed to make the current request.
     * @return <code>true</code> if request should be allowed access
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        // Or:
        //return super.isAccessAllowed(request, response, mappedValue) ;
        boolean b = accessYesOrNo(request, response) ;
        if ( log.isDebugEnabled() )
            log.debug("isAccessAllowed -> "+b);
        return b ;
    }
    
    /**
     * Processes unauthenticated requests.
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method.
     *
     * @return <code>false</code>. This method handles the HTTP 401 challenge.
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() )
            log.debug("onAccessDenied");
        HttpServletRequest httpRequest = WebUtils.toHttp(request) ;
        HttpServletResponse httpResponse = WebUtils.toHttp(response) ;
        engine.sendChallenge(httpRequest, httpResponse); 
        return false ;
    }
       
    /** The RFC 2617 algorithm for determing whether a request is acceptable or not.
     * See also {@link #sendChallenge(HttpServletRequest, HttpServletResponse)}.
     * @return <cod>true</code> if accepable, else <code>false</code>.
     */
    private boolean accessYesOrNo(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request) ;
        HttpServletResponse httpResponse = WebUtils.toHttp(response) ;
        return engine.accessYesOrNo(httpRequest, httpResponse) ;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        return false;
    }
    
    /** Return the password for the named user, or null if none found.
     * @param servletContext
     * @param username
     * @return Password or null (not found).
     */
    protected abstract String getPassword(ServletContext servletContext, String username) ;
    
    /** Return false - there is no special "login" request. */
    @Override
    protected final boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() ) 
            log.debug("isLoginRequest");
        return false ;
    }
    
    /** Create a token.
     * @See {@link AuthenticatingFilter#createToken}
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() ) log.debug("createToken"); 
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // Create an empty authentication token since there is no
            // Authorization header.
            return createToken("", "", request, response);
        }
        if (log.isDebugEnabled()) {
            log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

        // XXX Yuk - reparse.
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        AuthHeader ah = AuthHeader.parse(authorizationHeader, httpRequest.getMethod()) ;
        if ( ah == null )
            return createToken("", "", request, response);
        DigestSession perm = engine.getCredentials(ah.opaque) ;
        if ( perm == null )
            return createToken("", "");
        // Token is the user name and our generated reference (both are wire-visible). 
        return createToken(perm.username, perm.opaque);
    }
    
    private AuthenticationToken createToken(String username, String opaque) {
        return new DigestAuthenticationToken(username, opaque); 
    }

    /**
     * Builds the challenge for authorization by setting a HTTP <code>401</code> (Unauthorized) status as well as the
     * response's {@link #AUTHENTICATE_HEADER AUTHENTICATE_HEADER}.
     * @return false - this sends the challenge to be sent back.
     */
    protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication required: sending 401 Authentication challenge response.");
        }
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        engine.sendChallenge(httpRequest, httpResponse) ;
        return false;
    }

    /**
     * Returns the {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the specified ServletRequest.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the <code>Authorization</code> header's value.
     */
    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(AUTHORIZATION_HEADER);
    }

    /**
     * Default implementation that returns <code>true</code> if the specified <code>authzHeader</code>
     * starts with the same (case-insensitive) characters specified by the
     * {@link #getAuthzScheme() authzScheme}, <code>false</code> otherwise.
     */
    protected boolean isLoginAttempt(String authzHeader) {
        // Use Locale.ROOT - "I->i" : remain within ASCII (not so for Turkish, Lithuanian, and Azerbaijani).
        String authzScheme = DIGEST_AUTH.toLowerCase(Locale.ROOT);
        return authzHeader.toLowerCase(Locale.ROOT).startsWith(authzScheme);
    }
}
