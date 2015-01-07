# princeprocessor

Standalone password candidate generator using the PRINCE algorithm

# Brief Description

The princeprocessor is a password guess generator and can be thought of as an advanced Combinator attack. Rather than taking as input two different wordlists and then outputting all the possible two word combinations though, princeprocessor only has one input wordlist and builds "chains" of combined words. These chains can have 1 to N words from the input dictionary concatenated together. So for example if it is outputting guesses of length four, it could generate them using combinations from the input dictionary such as:

- 4 letter word
- 2 letter word + 2 letter word
- 1 letter word + 3 letter word
- 3 letter word + 1 letter word
- 1 letter word + 1 letter word + 2 letter word
- 1 letter word + 2 letter word + 1 letter word
- 2 letter word + 1 letter word + 1 letter word
- 1 letter word + 1 letter word + 1 letter word + 1 letter word

