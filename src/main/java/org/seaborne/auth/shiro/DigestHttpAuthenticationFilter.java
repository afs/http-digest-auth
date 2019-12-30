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
import org.seaborne.auth.DigestHttp.AccessStatus ;

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
import org.seaborne.auth.AuthResponseHeader ;
import org.seaborne.auth.DigestHttp ;
import org.seaborne.auth.DigestSession ;
import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

/** Perform HTTP Digest authentication (RFC 2617).
 * <p>
 * The actual algorithm is in {@link DigestHttp} and this class is an adapter for the 
 * <a href="https://shiro.apache.org/">Apache Shiro fraemwork</a>. 
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>
 * @see <a href="https://en.wikipedia.org/wiki/Digest_access_authentication">Wikipedia entry on Digest Access Authentication</a>
 * @see BasicHttpAuthenticationFilter
 */
public abstract class DigestHttpAuthenticationFilter extends AuthenticatingFilter {
    private static final Logger log = LoggerFactory.getLogger(DigestHttpAuthenticationFilter.class);

    /** HTTP Authorization header, equal to <code>Authorization</code> */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

    /** HTTP Authentication header, equal to <code>WWW-Authenticate</code> */
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /** The name of the scheme */ 
    private static String DIGEST_AUTH = HttpServletRequest.DIGEST_AUTH ;

    private DigestHttp engine;

    private String applicationName = "Login" ;

    protected DigestHttpAuthenticationFilter() {
        this.engine = new DigestHttp(log, applicationName, this::getPassword) ; 
    }

    // Code for two-stage process.
    //  See DigestHttpAuthenticationFilter2Step
    //  That needs to call accessYesOrNo twice (a second time on inAccessDenied to know if it is
    //    true or false) which makes any nc processing ugly.
    
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        // Do everything, including sending a challenge, in one step.
        // This way, the header is processed only once.
        // It's equiavlent to implementing "onPreHandle"
        return wholeProcess(request, response) ;
    }
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false ;
    }
    

    // Flatten:
    // Override onPreHandle --> 
    //    isAccessAllowed(request, response, mappedValue) || onAccessDenied(request, response, mappedValue);
    //      isAccessAllowed
    //        accessYesOrNo , isLoginRequest(request, response) , isPermissive(mappedValue))
    //      onAccessDenied
    //        accessYesOrNo , executeLogin,  sendChallenge 
    // Flatten to one operation and one call of "accessYesOrNo"
//    @Override
//    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
//        return wholeProcess(request, response) ;
//    }
    
    /** Execute the HTTP Digect authentication process and the Shiro login process.
     *  Calls accessYesOrNo once per requets, making "nc" processing cleaner. 
     */
    
    private boolean wholeProcess(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() ) { 
            String header = getAuthzHeader(request) ;
            log.debug("**** **** HTTP Digest Authentiation -> "+header);
        }
        AccessStatus decision = accessYesOrNo(request, response) ;
        switch ( decision ) {
            case BAD :
                // Have sent the 400
                return false ;
            case NO :
                sendChallenge(request, response) ;
                return false ;
            case YES :
                break;
        }
        
        Subject subject = getSubject(request, response);
        if ( subject.isAuthenticated() )
            return true ;
        try { return executeLogin(request, response) ; } 
        catch (Exception ex) { return false ; }
    }
    
    /** The RFC 2617 algorithm for determing whether a request is acceptable or not.
     * See also {@link #sendChallenge(HttpServletRequest, HttpServletResponse)}.
     * @return <cod>true</code> if accepable, else <code>false</code>.
     */
    private AccessStatus accessYesOrNo(ServletRequest request, ServletResponse response) {
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
    
    /**
     * Returns the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
     * <p/>
     * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
     * by the {@link #setApplicationName(String) setApplicationName(String)} method, the default value is 'application'.
     * <p/>
     * See {@link #setApplicationName(String) setApplicationName(String)}
     *
     * @return the name to use in the ServletResponse's 'WWW-Authenticate' header.
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Sets the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
     * <p/>
     * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
     * by this method, the default value is &quot;application&quot;
     * <p/>
     * Side note: As you can see from the header text, the HTTP Basic specification calls
     * this the authentication 'realm', but we call this the 'applicationName' instead to avoid confusion with
     * Shiro's Realm constructs.
     *
     * @param applicationName the name to use in the ServletResponse's 'WWW-Authenticate' header.
     */
    public void setApplicationName(String applicationName) {
        boolean newName = (applicationName == null || ! applicationName.equals(this.applicationName) ) ;
        this.applicationName = applicationName;
        if ( newName )
            // Drop old state.
            this.engine = new DigestHttp(log, applicationName, this::getPassword) ; 
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
            return untoken(request, response) ;
        }
        if (log.isDebugEnabled()) {
            log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

        // XXX Yuk - reparse to get user.
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        AuthResponseHeader ah = AuthResponseHeader.parse(authorizationHeader, httpRequest.getMethod()) ;
        if ( ah == null )
            return createToken("", "", request, response);
        DigestSession perm = engine.getCredentials(ah.opaque) ;
        if ( perm == null )
            return untoken(httpRequest, response) ;
        // Token is the user name and our generated reference (both are wire-visible). 
        String password = getPassword(request.getServletContext(), perm.username) ;
        
        //return createToken(perm.username, password);
        return createToken(perm.username, password, request, response);
    }
    
    private AuthenticationToken untoken(ServletRequest request, ServletResponse response) {
        return createToken("", "", request, response);
    }
    
    // XXX Would like to use opaque as the credentials but other Shiro steps need the true password. ???
//    private AuthenticationToken createToken(String username, String opaque) {
//        return new DigestAuthenticationToken(username, opaque); 
//    }

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
