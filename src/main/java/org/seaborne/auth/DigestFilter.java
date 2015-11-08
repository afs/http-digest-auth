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

import java.io.BufferedInputStream ;
import java.io.FileInputStream ;
import java.io.IOException ;
import java.io.InputStream ;
import java.util.HashMap ;
import java.util.Map ;
import java.util.Properties ;
import java.util.regex.Pattern ;

import javax.servlet.* ;
import javax.servlet.http.HttpServletRequest ;
import javax.servlet.http.HttpServletResponse ;

import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

public class DigestFilter implements Filter {
    private static Logger log = LoggerFactory.getLogger(DigestFilter.class) ;
    public static String passwordFileInit = "password-file" ;
    public static String realmInit = "realm" ;
    public static String urlPatternInit = "urlPattern" ;
    
    private Map<String, String> credential;
    private Pattern urlPattern = null ;
    private DigestHttp engine ;
    private Map<String, String> credentials;
    private String realm; 

    public DigestFilter() { }
    
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("DigestFilter.init"); 
        String fn = filterConfig.getInitParameter(passwordFileInit) ;
        if ( fn == null )
            throw new ServletException("No 'passwordFile") ;
        this.credentials = parsePasswordfile(fn) ;
        String urlPatternStr = filterConfig.getInitParameter(urlPatternInit) ;
        if ( urlPatternStr != null )
            this.urlPattern = Pattern.compile(urlPatternStr) ;
        this.realm =  filterConfig.getInitParameter(realmInit) ;
        if ( this.realm == null ) {
            log.warn("Init-param 'realm' not found: defaults to 'Login'");
            this.realm = "Login" ; 
        }
        
        this.engine = new DigestHttp(null, realm, (x,u)->credentials.get(u)) ;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
        throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest)request ;
        HttpServletResponse httpResponse = (HttpServletResponse)response ;
        //getContextPath
        String url = httpRequest.getRequestURI() ;
        //httpRequest.getRequestURL() ;
        if ( urlPattern == null || urlPattern.matcher(url).matches() ) {
            DigestHttp.AccessStatus status = engine.accessYesOrNo(httpRequest, httpResponse) ;
            log.info("Check "+url+" "+status);
            switch(status) {
                case BAD :
                    return ;
                case NO :
                    engine.sendChallenge(httpRequest, httpResponse);
                    return ;
                case YES :
                    break;
            }
        } else {
            log.info("Pass "+url);
        }
        
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    private static Map<String, String> parsePasswordfile(String fn) throws ServletException {
        Properties properties = new Properties();
        try ( InputStream in = new BufferedInputStream(new FileInputStream(fn)) ) {
            properties.load(in) ;
        } catch (IOException e) {
            throw new ServletException("Failed to read password file", e) ;
        }
        Map<String, String> credentials = new HashMap<>() ;
        properties.forEach((k,v) ->
            credentials.put((String)k, (String)v)
        ) ;
        //log.info(credentials.toString()) ;
        return credentials ;
    }

}
