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

import javax.servlet.ServletContext ;

import org.apache.shiro.config.Ini.Section ;
import org.apache.shiro.web.env.IniWebEnvironment ;
import org.apache.shiro.web.util.WebUtils ;
import org.slf4j.LoggerFactory ;

/** HTTP Digest authentication, getting the password from the [users] section of a Shiro ini file. */
public class DigestHttpAuthenticationFilterIniPassword extends DigestHttpAuthenticationFilter {

    private volatile boolean initialized = false ;
    private          Section usersSection = null ; 
        
    public DigestHttpAuthenticationFilterIniPassword() {
        super() ;
    }

    @Override
    protected String getPassword(ServletContext servletContext, String username) {
        if ( username == null )
            return null ;
        return usersSection(servletContext).get(username) ;
    }
    
    // Delayed initialization of usersSection
    // The servlet context isn't ready when the constructior runs. 
    private Section usersSection(ServletContext servletContext) {
        if ( !initialized ) {
            synchronized (this) {
                try {
                    if ( initialized )
                        return usersSection;
                    initialized = true;
                    IniWebEnvironment env = (IniWebEnvironment)WebUtils.getWebEnvironment(servletContext) ; 
                    usersSection = env.getIni().getSection("users") ;
                } catch (Exception ex) {
                    LoggerFactory.getLogger(getClass()).error("Failed to find the shiro.ini [users] section"); 
                }
            }
        }
        return usersSection ; 
    }
}