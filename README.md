princeprocessor
==============

Standalone password candidate generator using the PRINCE algorithm

Brief description
--------------

The princeprocessor is a password candidate generator and can be thought of as an advanced combinator attack. Rather than taking as input two different wordlists and then outputting all the possible two word combinations though, princeprocessor only has one input wordlist and builds "chains" of combined words. These chains can have 1 to N words from the input wordlist concatenated together. So for example if it is outputting guesses of length four, it could generate them using combinations from the input wordlist such as:

- 4 letter word
- 2 letter word + 2 letter word
- 1 letter word + 3 letter word
- 3 letter word + 1 letter word
- 1 letter word + 1 letter word + 2 letter word
- 1 letter word + 2 letter word + 1 letter word
- 2 letter word + 1 letter word + 1 letter word
- 1 letter word + 1 letter word + 1 letter word + 1 letter word

Detailed description
--------------

I'm going to write a detailed description in case I'm extremely bored. Till that, use the following resources:

- My talk about princeprocessor on Passwords^14 conference in Trondheim, Norway. Slides: https://hashcat.net/tools/princeprocessor/prince-attack.pdf
- Thanks to Matt Weir, he made a nice analysis of princeprocessor. You can find the post on his blog: http://reusablesec.blogspot.de/2014/12/tool-deep-dive-prince.html

Compile
--------------

If you want to compile from source make sure you have GMP libraries and headers installed. 

- On Ubuntu: `apt-get install libgmp-dev`

Binary distribution
--------------

Binaries for Linux, Windows and OSX can be found here: https://hashcat.net/tools/princeprocessor/
