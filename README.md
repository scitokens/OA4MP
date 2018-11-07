# SciTokens for Java

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.1206233.svg)](https://doi.org/10.5281/zenodo.1206233)
[![Build Status](https://travis-ci.org/scitokens/scitokens-java.svg?branch=master)](https://travis-ci.org/scitokens/scitokens-java)
[![Javadocs](https://www.javadoc.io/badge/org.scitokens/scitokens-client.svg)](https://www.javadoc.io/doc/org.scitokens/scitokens-client)

## Prerequisites

* Java 8+
* [Maven](https://maven.apache.org/) 3.0+

## Docs

https://scitokens.org/

## Notes

This is standard OA4MP with an extension to handle SciTokens. 
You should set the OIDCEnabled flag to false 
(see here: http://grid.ncsa.illinois.edu/myproxy/oauth/server/dtd/server-dtd-service-tag.xhtml) and there is one additional configuration flag specific to SciTokens that needs to be set true, , 
issueATasSciToken = issue the Access Tokens as a SciToken. 
A snippet of the configuration might look like this:
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

 
There is a template document as well at https://docs.google.com/document/d/1R9d5RI_4RgDlsiOmTK7_XVhjRaoNIXW_DijGKQ-YtZk/edit#
