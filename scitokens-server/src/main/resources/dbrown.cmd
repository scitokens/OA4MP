# A command file to run the SciTokens configuration for Duncan Brown
# This requires that we restrict it to him alone (until they set up their LDAP)
# so that only his eppn of dabrown@sry.edu can get the permissions of
#  https://sugwg-scitokens.phy.syr.edu:8080/key/5d878113798a0d687e5139fb347f6b7932b37477d9e80be29ee7c43807e6ba03

setEnv('eppn','dabrown@syr.edu');
echo('eppn=${eppn}');

if[
  equals('${eppn}','dabrown@syr.edu')
 ]then[
    echo('foo'),echo('fnord'),set('read','read:/user/dbrown')
  ]else[
  echo('bar')
];

echo(get('read'));