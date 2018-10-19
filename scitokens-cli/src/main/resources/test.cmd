# First batch mode test
# The comment marker is the pound sign, #. If that is the first non-blank character, the line is ignored.
# Each command ends with a semi-colon ;. This means that lines are concatenated until a line ends with a
# semi-colon, then that is treated as a command. Note that the semi-colon will be removed.
# This generally ignores whitespace and blank lines too...
# And do set a log file and read it. You can get quite a good running
# commentary.


set_no_output false;

# Print out a JSON webkey file and splay the command over a couple of lines:
list_keys
   /home/ncsa/dev/scitokens-git/test/keys.jwk;

set_keys -file /home/ncsa/dev/scitokens-git/test/keys.jwk;
set_no_output true;
set_default_id "A60914779FC1C785D3C0E33F1AB6ADFE";
print_default_id
# The next few lines are not a command. This shows that the processor will simply skip any commands
# it does not recognize.
fnord
  blarg
   *^$$8&;

# Create a new set of keys and stash them in a file:

create_keys /tmp/keys1.jwk;
# Turn output back on, re-issue the print default id command
set_no_output false;
print_default_id;

