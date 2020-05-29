# aclline

Application add "permit" line to acccess-list which name can be found in "acl_name_in  acl_name_out" variables.

Username, password and IP can be found in ssh_connect func.

libssh is used here to connect to ios device.  - https://www.libssh.org/

File "id.txt" should be created before using app. File contain number which will be used in access-list as id for "permit" line. Init line is set in "define MIN_ID".