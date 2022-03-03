# Mix-Server

A mix server is a security feature that improves anonymity by serving as a middle-man between person A (client) and person B (another server).
it works by storing all the messages that it receives witthing a certain amount of time (1 minute here) and then sending each one to its destination in a randomized order.
If there is an attcker with listening capabilities on the network, thay wouldn't be able to track the messages since by the time they're sent the attcker wouldn't know which message came from where.

This is a modular implementation, meaning that t supports transferring the message through any number of mix servers before it reaches its destination.
Additionally, it uses asymetric enchryption to increase security.

For run arguments, see 'appendix.pdf'
