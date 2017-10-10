<%--
  User: Jeff Gaynor
  Date: 9/27/11
  Time: 4:58 PM

    NOTE:This page is supplied as an example and under no circumstances should ever be deployed
  on a live server. It is intended to show control flow as simply as possible.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Simple client success page.</title></head>
<style type="text/css">
    .hidden {
        display: none;
    }

    .unhidden {
        display: block;
    }
</style>
<script type="text/javascript">
    function unhide(divID) {
        var item = document.getElementById(divID);
        if (item) {
            item.className = (item.className == 'hidden') ? 'unhidden' : 'hidden';
        }
    }
</script>
<script type="text/javascript">
    function wordwrap(str, width, brk, cut) {
        brk = brk || 'n';
        width = width || 75;
        cut = cut || false;
        if (!str) {
            return str;
        }
        var regex = '.{1,' + width + '}(\s|$)' + (cut ? '|.{' + width + '}|.+$' : '|\S+?(\s|$)');
        return str.match(RegExp(regex, 'g')).join(brk);
    }
</script>

<body>
<h1>Success!</h1>

<table border="1">
    <tr>
        <td>Token</td>
        <td>
            <pre>${st_accessToken}</pre>
        </td>
    </tr>
    <tr>
        <td>Header</td>
        <td>
            <pre>${st_header}</pre>
        </td>
    </tr>
    <tr>
        <td>Payload</td>
        <td>
            <pre>${st_payload}</pre>
        </td>
    </tr>
    <tr>
        <td>Public key</td>
        <td><pre>${st_public_key}</pre></td>
    </tr>

    <tr>
        <td>Verified?</td>
        <td><b>${st_verified}</b></td>
    </tr>
</table>


<form name="input" action="${action}" method="get"/>
<input type="submit" value="Return to client"/>
</form>
</body>
</html>