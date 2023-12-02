# Rosetta Secure Texting
Rosetta is an instant text-messaging application designed with utmost security and privacy not only in mind, but as its main feature! That's right, modern cryptographic algorithms and their proper usage ensure it's mathematically impossible for anyone to ever find out what you're saying on Rosetta. It is
room-oriented, you're able to create your own new chatroom, or enter someone else's existing chatroom, after registering.

Many thanks to fgrieu, moderator at crypto.stackexchange.com, for all the extensive know-how he has personally shared with me about relevant topics in cryptography. Without him
it would have been close to impossible to get the theoretical security aspect of this correct.

I am implementing everything myself from scratch:

- A BigNum arithmetic library in C, since cryptographic algorithms often require working with huge numbers of thousands of digits to be secure.
- A cryptographic library in C. These algorithms are to be used to construct the actual security scheme of the chatting application.
- Server and Client desktop applications in C, using Linux Sockets to enable communication between the client's machine and the server.
- Desktop GUI, probably will write in wxWidgets or GTK+.

The Big Number arithmetic library supports:
- Constructing BigInts in various ways. Arithmetic is done on little-endian unsigned big integers.
- Adding, Subtracting, Multiplying, Dividing two BigInts.
- Comparing two BigInts.
- Switching the endianness of a BigInt
- Equating one BigInt to another
- BigInt to the power of another BigInt
- Multiplication of 2 or more BigInts, modulo another BigInt
- BigInt to the power of another BigInt, modulo a third BigInt

The cryptographic algorithms implemented are:
- Diffie-Hellman
- BLAKE2B
- ChaCha20 
- Argon2id
- Schnorr Signature generator
- Rabin-Miller primality test on my BigNums
