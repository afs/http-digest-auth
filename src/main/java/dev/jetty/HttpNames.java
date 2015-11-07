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

public class HttpNames {
    public static final String hAccept              = "Accept" ;
    public static final String hAcceptEncoding      = "Accept-Encoding" ;
    public static final String hAcceptCharset       = "Accept-Charset" ;
    public static final String hAcceptRanges        = "Accept-Ranges" ;
    
    public static final String hAllow               = "Allow" ;
    public static final String hContentEncoding     = "Content-Encoding" ;
    public static final String hContentLengh        = "Content-Length" ;
    public static final String hContentLocation     = "Content-Location" ;
    public static final String hContentRange        = "Content-Range" ;
    public static final String hContentType         = "Content-Type" ;
    public static final String hPragma              = "Pragma" ;
    public static final String hCacheControl        = "Cache-Control" ;
    public static final String hRetryAfter          = "Retry-After" ;
    public static final String hServer              = "Server" ;
    public static final String hLocation            = "Location" ; 
    public static final String hVary                = "Vary" ;
    public static final String charset              = "charset" ;
    
    // CORS: 
    //   http://www.w3.org/TR/cors/  http://esw.w3.org/CORS_Enabled
    public static final String hAccessControlAllowOrigin        = "Access-Control-Allow-Origin" ;
    public static final String hAccessControlExposeHeaders      = "Access-Control-Expose-Headers" ;
    public static final String hAccessControlMaxAge             = "Access-Control-Max-Age" ;
    public static final String hAccessControlAllowCredentials   = "Access-Control-Allow-Credentials" ; 
    public static final String hAccessControlAllowMethods       = "Access-Control-Allow-Methods" ;
    public static final String hAccessControlAllowHeaders       = "Access-Control-Allow-Headers" ;
    public static final String hOrigin                          = "Origin" ;
    public static final String hAccessControlRequestMethod      = "Access-Control-Request-Method" ;
    public static final String hAccessControlRequestHeaders     = "Access-Control-Request-Headers" ;
    
    public static final String METHOD_DELETE        = "DELETE";
    public static final String METHOD_HEAD          = "HEAD";
    public static final String METHOD_GET           = "GET";
    public static final String METHOD_OPTIONS       = "OPTIONS";
    public static final String METHOD_PATCH         = "PATCH" ;
    public static final String METHOD_POST          = "POST";
    public static final String METHOD_PUT           = "PUT";
    public static final String METHOD_TRACE         = "TRACE";

    public static final String HEADER_IFMODSINCE    = "If-Modified-Since";
    public static final String HEADER_LASTMOD       = "Last-Modified";
}

