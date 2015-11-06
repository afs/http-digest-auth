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

package dev;

public class DevProcess {
    // "Digest request" operation.
    //   isFirst (i.e not logged in)
    // Digest : method and URI from request  
    // checking nc= cnonce= method= uri=

    // setAttribute to avoid reparsing.  ?? No need - only happens on login attempt
    
    //Head: Authorization = Basic dTE6cHcxMjM=
    // u1, pw123
    
    //Head: Authorization = Basic dTI6cHc0NTY=
    // u2, pw456
    
    // BasicHttpAuthenticationFilter
    // isLoginAttempt  called twice.
    //   Once from isAccessAllowed, isLoginRequest, once from 
    
    // AccessControlFilter.onPreHandle = isAccessAllowed || onAccessDenied
    // isAccessAllowed -> isLoginRequest -> isLoginAttempt
    // onAccessDenied -> isLoginAttempt
    
    // Tests
}
