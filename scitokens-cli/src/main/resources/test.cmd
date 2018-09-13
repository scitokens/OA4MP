// First batch mode test
// The comment marker is the double slash, //. Anything after that on a line is ignored.
// If you need to extend a command over several lines, e.g. for readability, you
// can use the single back slash at the end of a line, \  You cannot have blank lines
// though if you are using the continuation character.
//
// This generally ignores whitespace and blank lines too...
// And do set a log file and read it. You can get quite a good running
// commentary.


set_no_output false // so this spits out results to the screen

// Print out a JSON webkey file and splay the command over a couple of lines:
list_keys \ // More commentary:
   /home/ncsa/dev/scitokens-git/test/keys.jwk // And another comment.

set_keys -file /home/ncsa/dev/scitokens-git/test/keys.jwk
set_no_output true // Turn off output and try to print -- nothing should show up.
set_default_id "A60914779FC1C785D3C0E33F1AB6ADFE"
print_default_id
// The next few lines are not a command. This shows that the processor will simply skip any commands
// it does not recognize.
fnord \
  blarg \
   *^$$8&

// Create a new set of keys and stash them in a file:

create_keys /tmp/keys1.jwk
set_no_output false // Turn output back on, re-issue the print default id command
print_default_id

