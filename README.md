## HTTP Digest Authentication

    https://github.com/afs/http-digest-auth
    org.seaborne:http-digest-auth

Why digest authentication?


Sometimes, something lighter than https is the needed or not
assuming https setup. https is not easy to setup.

For example, from a small device or when making a few API calls.

But basic authentication over http is revealing the password.
At least digest authentication does not reveal the shared secret.    

Use with care. "better than nothing" is not a general security solution.

This repository has code for:

* A HTTP digest (RFC2617) engine
* Stand-alone servlet filter
* An integration with [Apache Shiro](https://shiro.apache.org)
