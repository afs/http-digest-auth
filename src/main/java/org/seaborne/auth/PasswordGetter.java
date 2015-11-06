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

import javax.servlet.ServletContext ;

/** Interface to express mapping user to password.
 * There may be different ways to manage password.  Teh Digest algoritms
 * does not say how they are managed.
 */
@FunctionalInterface
public interface PasswordGetter {
    /** Returns the password for the username, or null for "not found".
     * @param servletContext
     * @param username
     * @return String, with null for "not found"
     */
    public String getPassword(ServletContext servletContext, String username);
}