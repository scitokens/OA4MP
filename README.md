# SciTokens for Java

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.1206233.svg)](https://doi.org/10.5281/zenodo.1206233)
[![Build Status](https://travis-ci.org/scitokens/scitokens-java.svg?branch=master)](https://travis-ci.org/scitokens/scitokens-java)
[![Javadocs](https://www.javadoc.io/badge/org.scitokens/scitokens-client.svg)](https://www.javadoc.io/doc/org.scitokens/scitokens-client)

## Prerequisites

* Java 8+
* [Maven](https://maven.apache.org/) 3.0+
* Tomcat 7 or above
* Java mail (see [here](http://grid.ncsa.illinois.edu/myproxy/oauth/server/configuration/server-email.xhtml)
* Some form of persistent storage, such as Postgres, MySQL, MariaDB or a file system. 
  See the specific sections [here](http://grid.ncsa.illinois.edu/myproxy/oauth/server/configuration/config-index.xhtml)

## Docs

https://scitokens.org/

## Notes

### For the server
This is standard [OA4MP](http://grid.ncsa.illinois.edu/myproxy/oauth/server/index.xhtml) with an extension to handle SciTokens.
So pretty much all of the standard OA4MP documentation and features work.  
The default for OA4MP is OIDC, so you should set the OIDCEnabled flag to false unless you need OIDC support 
(see [here](http://grid.ncsa.illinois.edu/myproxy/oauth/server/dtd/server-dtd-service-tag.xhtml)) 
and there is one additional configuration flag specific to SciTokens that needs to be set true,
```aidl
issueATasSciToken = issue the Access Tokens as a SciToken. 
```  
Otherwise a non-SciToken will be generated as the access token. (That would be used in a very specific case, where
it is presented to the the token exchange endpoint to get a SciToken.) A snippet of the configuration might look like this:
```XML
<service  name="my.scitokens.server"
          issueATasSciToken="true"
          OIDCEnabled="false"
          refreshTokenLifetime="1000000"
          refreshTokenEnabled="true"
          scheme="sciTokens"
          schemeSpecificPart=""
          clientSecretLength="40"
          debug="trace">
  <!-- other stuff -->
 </service>
 ```
### For clients

Once you have a server up and running, you need to [register and configure clients](http://grid.ncsa.illinois.edu/myproxy/oauth/client/configuration/index.xhtml) 
in order to get SciTokens.  
There is a template document as well [here](https://docs.google.com/document/d/1R9d5RI_4RgDlsiOmTK7_XVhjRaoNIXW_DijGKQ-YtZk/edit#).
Templates tell the server how the client should create it SciTokens. There is a lot of flexibility in what
can be done since there is a strong [scripting language](https://docs.google.com/document/d/1BtlCbvGCcjblgtCNnaC09QLktXksxVD-P9dTvz1HAMQ/edit?usp=sharing) backing the configurations. Creation of SciTokens can be 
dictated as well based on the claims (which are best viewed as metadata) about the user.  

You may also manipulate SciTokens (which includes many other useful utilities) using the [command line 
utilities](https://docs.google.com/document/d/10ShyuYuouaRyE-hDMAhBYZCmSzlJtUkuY4bkqtDHmZw/edit?usp=sharing)