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

import javax.servlet.ServletContext ;
import javax.servlet.ServletContextEvent ;
import javax.servlet.ServletContextListener ;

import org.apache.shiro.config.ConfigurationException ;
import org.apache.shiro.web.env.EnvironmentLoader ;
import org.slf4j.Logger ;
import org.slf4j.LoggerFactory ;

/** A place to perform initialization of Apache Shiro.
 *  This means finding shiro.ini in multiple possible places,
 *  based on different deployment setups.
 */
public class ShiroEnvironmentLoader extends EnvironmentLoader implements ServletContextListener {
    private ServletContext servletContext ; 
    private static Logger log = LoggerFactory.getLogger(ShiroEnvironmentLoader.class) ;
    
    public ShiroEnvironmentLoader() {}
    
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        this.servletContext = sce.getServletContext() ;
        try { 
            // Shiro.
            log.info("Shiro initialization");
            initEnvironment(servletContext);
        } catch (ConfigurationException  ex) {
            log.error("Shiro initialization failed: "+ex.getMessage());
            // Exit?
            throw ex ;
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        destroyEnvironment(sce.getServletContext());
    }

//    /** 
//     * Normal Shiro initialization only supports one location for an INI file.
//     *  
//     * When given multiple multiple locations for the shiro.ini file, and 
//     * if a {@link ResourceBasedWebEnvironment}, check the list of configuration
//     * locations, testing whether the name identified an existing resource.  
//     * For the first resource name found to exist, reset the {@link ResourceBasedWebEnvironment}
//     * to name that resource alone so the normal Shiro initialization  
//     */
//    @Override
//    protected void customizeEnvironment(WebEnvironment environment) {
//        if ( environment instanceof ResourceBasedWebEnvironment ) {
//            ResourceBasedWebEnvironment env = (ResourceBasedWebEnvironment)environment ;
//            String[] locations = env.getConfigLocations() ;
//            String loc = huntForShiroIni(locations) ;
//            log.info("Shiro file: "+loc);
//            if (loc != null )
//                locations = new String[] {loc} ;
//            env.setConfigLocations(locations);
//        }
//    }
//    
//    private static final String FILE = "file" ;
//    
//    /** Look for a Shiro ini file, or return null */
//    private static String huntForShiroIni(String[] locations) {
//        for ( String loc : locations ) {
//            // If file:, look for that file.
//            // If a relative name without scheme, look in FUSEKI_BASE, FUSEKI_HOME, webapp. 
//            String scheme = getScheme(loc) ;
//            
//            // Covers C:\\ as a "scheme name"
//            if ( scheme != null ) {
//                if ( scheme.equalsIgnoreCase(FILE)) {
//                    // Test file: for exists
//                    Path p = Paths.get(loc.substring(FILE.length()+1)) ;
//                    if ( ! p.toFile().exists() )
//                        continue ;
//                    // Fall through.
//                }
//                // Can't test - try 
//                return loc ;
//            }
//            // No scheme .
//            Path p = Paths.get(loc) ;
//            
////            String fn = resolve(FusekiEnv.FUSEKI_BASE, p) ;
////            if ( fn != null )
////                return "file://"+fn ;
////            fn = resolve(FusekiEnv.FUSEKI_HOME, p) ;
////            if ( fn != null )
////                return "file://"+fn ;
//            
//            // Try in webapp.
//            
//            try ( InputStream is = ResourceUtils.getInputStreamForPath(loc); ) {
//                boolean exists = (is != null ) ;
//                return loc ;
//            } catch (IOException e) { }
//        }
//        return null ;
//    }
//    
//    /** Directory + name -> filename if it exists */ 
//    private static String resolve(Path dir, Path file) {
//        Path p = dir.resolve(file) ;
//        if ( p.toFile().exists() )
//            return p.normalize().toString() ;
//        return null ;
//    }
//
//    
//    public static String getScheme(String uri)
//    {
//        // Find "[^/:]*:.*"
//        for ( int i = 0 ; i < uri.length() ; i++ )
//        {
//            char ch = uri.charAt(i) ;
//            if ( ch == ':' )
//                return uri.substring(0,i) ;
//            if ( ! isASCIILetter(ch) )
//                // Some illegal character before the ':' 
//                break ;
//        }
//        return null ;
//    }
//    
//    private static boolean isASCIILetter(char ch)
//    {
//        return ( ch >= 'a' && ch <= 'z' ) || ( ch >= 'A' && ch <= 'Z' ) ;
//    }
////    /** 
////     * Test whether a name identified an existing resource
////     * @param resource    A String in Shiro-resource name format (e.g. URL scheme names) 
////     * @return True/false as to whether the resource can be found or not. 
////     */
////    
////    private boolean resourceExists(String resource) {
////        try {
////            // See IniWebEnvironment.convertPathToIni
////            if (!ResourceUtils.hasResourcePrefix(resource)) {
////                //Sort out "path" and open as a webapp resource.
////                resource = WebUtils.normalize(resource);
////                URL url = servletContext.getResource(resource) ;
////                return ( url == null ) ;
////            } else {
////                // Treat as a plain name. 
////                InputStream is = ResourceUtils.getInputStreamForPath(resource);
////                boolean exists = (is != null ) ;
////                is.close() ;
////                return exists ;
////            }
////        } catch (IOException e) { return false ; }
////    }
}
