# twamp-dissector

Wireshark dissector for TWAMP.
 
Written by Kristofer Hallin, 2014.
Email: kristofer dot hallin at gmail dot com


## Building

1. Obtain the source code for Wireshark.

   The code can be found here: https://www.wireshark.org/download.html
   I have only build this with version 1.12.

2. Enter the directory build/ and from there type 'cmake ..' That will
   generate a Makefile and other necessary files.

3. From the directory build/ enter the command 'make'. This will
   compile the code and (hopefully) create a file called "twamp.so".

4. Copy "twamp.so" to your plugins directory. This is usually
   "~/.wireshark/plugins/". Restart Wireshark.