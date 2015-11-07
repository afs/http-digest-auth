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

package dev.jetty;

import org.apache.jena.atlas.lib.FileOps ;
import org.eclipse.jetty.server.HttpConnectionFactory ;
import org.eclipse.jetty.server.Server ;
import org.eclipse.jetty.server.ServerConnector ;
import org.eclipse.jetty.webapp.WebAppContext ;
import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

/** Jetty test setup */
public class RunJetty {
    private static Logger log = LoggerFactory.getLogger(RunJetty.class) ; 
    
    public static void exec(int port) {
        defaultServerConfig(port, false) ;
        WebAppContext webappCxt = createWebApp("/") ;
        // webappCxt.addServlet
        // webappCxt.addFilter
        server.setHandler(webappCxt); 
        try {
            server.start();
        }
        catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(0) ;
        }
    }
    
    // The jetty server.
    private static Server          server          = null;
    private static ServerConnector serverConnector = null;

    private static void defaultServerConfig(int port, boolean loopback) {
        server = new Server() ;
        HttpConnectionFactory f1 = new HttpConnectionFactory() ;
        // Some people do try very large operations ... really, should use POST.
        f1.getHttpConfiguration().setRequestHeaderSize(512 * 1024);
        f1.getHttpConfiguration().setOutputBufferSize(5 * 1024 * 1024) ;
        
        //SslConnectionFactory f2 = new SslConnectionFactory() ;
        
        ServerConnector connector = new ServerConnector(server, f1) ; //, f2) ;
        connector.setPort(port) ;
        server.addConnector(connector);
        if ( loopback )
            connector.setHost("localhost");
        serverConnector = connector ;
    }

    // Standalone jar
    public static final String resourceBase1   = "webapp" ;
    // Development
    public static final String resourceBase2   = "src/main/webapp" ;
    
    private static WebAppContext createWebApp(String contextPath) {
        WebAppContext webapp = new WebAppContext();
        webapp.getServletContext().getContextHandler().setMaxFormContentSize(10 * 1000 * 1000) ;

        String resourceBase = tryResourceBase(resourceBase1, null) ;
        resourceBase = tryResourceBase(resourceBase2, resourceBase) ;
        
        if ( resourceBase == null )
            throw new RuntimeException("Can't find resourceBase (tried '"+resourceBase1+"' and '"+resourceBase2+"')") ;
        log.info("ResourceBase = "+resourceBase) ;
        webapp.setDescriptor(resourceBase+"/WEB-INF/web.xml");
        webapp.setResourceBase(resourceBase);
        webapp.setContextPath(contextPath);

        webapp.setDisplayName("Jetty") ;  
        webapp.setErrorHandler(new JettyErrorHandler()) ;
        return webapp ;
    }
    
    private static String tryResourceBase(String maybeResourceBase, String currentResourceBase) {
        if ( currentResourceBase != null )
            return currentResourceBase ;
        if ( maybeResourceBase != null && FileOps.exists(maybeResourceBase) )
            return maybeResourceBase ;
        return currentResourceBase ;
    }
}
