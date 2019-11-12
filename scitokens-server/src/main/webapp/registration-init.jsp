<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
    <title>SciTokens Client Registration Page</title>
</head>
<body>
<form action="${actionToTake}" method="post">
    <h2>Welcome to the SciTokens Client Registration Page</h2>

    <p>This page allows you to register your client with the
        OAuth 2 SciTokens service. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document. (This document is a bit old
        and will be updated at some point.)
    </p><br>
    <table>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="${clientNameValue}"/></td>
        </tr>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="${clientEmailValue}"/></td>
        </tr>
        <tr>
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="${clientHomeUrlValue}"/></td>
        </tr>
        <tr>
            <td>Callback URLs:</td>
            <td>
                    <textarea id="${callbackURI}" rows="5" cols="80"
                              name="${callbackURI}">${callbackURIValue}</textarea>
            </td>
        </tr>
        <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="${rtLifetimeValue}"/>(in
                seconds - leave blank for no refresh tokens.)
            </td>
        </tr>
        <tr>
            <td>User claim key:</td>
            <td><input type="text" size="25" name="${userClaimKey}" value="${userClaimKeyValue}"/>
                (Note this defaults to the "sub" claim if blank.)</td>
        </tr>

    </table>
   <H2>Enter your SciTokens audiences and scope request templates. </H2>

    <table>
        <tr>
            <th style="text-align: top">Audience</th>
            <th colspan="2">Templates</th>
        </tr>
        <tr>
            <td style="text-align: top"><input type="text" size="25" name="${aud0}" value="${aud0Value}"/></td>
            <td>
                 <textarea id="${templates0}" rows="5" cols="80"
                           name="${templates0}">${templates0Value}</textarea>
            </td>
        </tr>
        <tr>
            <td style="text-align: top"><input type="text" size="25" name="${aud1}" value="${aud1Value}"/></td>
            <td>
                 <textarea id="${templates1}" rows="5" cols="80"
                           name="${templates1}">${templates1Value}</textarea>
            </td>
        </tr>
        <tr>
            <td><input type="text" size="25" name="${aud2}" value="${aud2Value}"/></td>
            <td>
                 <textarea id="${templates2}" rows="5" cols="80"
                           name="${templates2}">${templates2Value}</textarea>
            </td>
        </tr>
        <tr>
            <td><input type="text" size="25" name="${aud3}" value="${aud3Value}"/></td>
            <td>
                 <textarea id="${templates3}" rows="5" cols="80"
                           name="${templates3}">${templates3Value}</textarea>
            </td>
        </tr>

    </table>

    <table>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>

    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>
</form>
<h3>A little explanation about audiences and templates.</h3>
<p>These refer to SciToken specific scopes. Audiences are associated with sets of scope
    templates. The templates allow you to specify what access you permit. Templates may
    end in <code>**</code> wildcards indicating any sub-path will be accepted.
    You should enter only a single template per line. A typical template would like like</p>
<pre>read:/public/**</pre>
<p>To give read access to everything in the /public directory and below it.
    You may also use variables such as</p>
<ul>
    <li>&#x24;{user} = the user's name at logon. This is taken from the claim given above.</li>
    <li>&#x24;{group} = IF there is group information associated with this user (e.g. in LDAP) then you may
    access the name of the group here. </li>
</ul>
<p>For instance if a user is in the groups <code>admin,users,gravity</code> then a permission template might look
like <code>read:/home/&#x24;{user}/&#x24;{group}/**</code> and if user bob could make the following specific request
against this template: <code>read:/home/bob/gravity/data/raw.hdf</code></p>
</body>
</html>