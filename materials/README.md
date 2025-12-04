# Rosetta Secure Texting

Rosetta is my latest hobby project - a secure chat system fully from scratch.

All cryptography, authentication, application-level network protocol, security
details and the crazy mathematics needed for it has been implemented by me, solo
from scratch in C, using no dependencies other than the C standard library,
syscalls and standard compiler extensions. Only the native desktop GUI has been
written using wxWidgets in C++.

Additionally, a Test Framework that I've developed allows the chat system and
its security to be tested locally on a single machine and OS. It simulates real
people texting each other by having local OS processes talking over AF_UNIX
sockets for local interprocess communications instead of Internet sockets.
A set of function pointers hides these two different interfaces, exposing to
the rest of the system a clean generalized communication API.

The 4 big components of Rosetta:

- BigInt math engine
- Cryptograhy engine
- TCP Server
- TCP Client

Rosetta implements a security protocol where each client machine and the server
have their own 320-bit private key generated from an acceptable pseudorandom
source and a 3080-bit public key derived from the private key, using three
cryptographic constants M, Q and G, which are found by my own search software
that utilizes the BigInt math engine to find M and Q and compute G out of them.

In particular: M is a 3080-bit prime integer, Q is a 320-bit prime integer that
               exactly divides (M-1) and G = [2 ^ ((M-1) / Q)] mod M.

Public keys are then computed based on M, G and the private key:

A = G^a mod M

where a is the private key and A is the corresponding public key.

The private key is always stored in encrypted form on the machine. A memorized
password is entered and used as a key in Argon2, which produces a hash out of
the password. That hash is then used as a key to ChaCha20 to encrypt / decrypt
the stored private key.

Diffie-Hellman shared secrets are computed by any two sides that wish to
communicate securely without anyone ever finding out what they've said.
Both sides end up with the same DH shared secret and they extract a
bidirectional pair of session keys KAB and KBA. The other side's public key
is used to compute a shared secret with them. The Rosetta Security Scheme has
details on how both sides send each other's public keys themselves in encrypted
form, to bootstrap the communication.

Two computers never know how to talk to each other, even if they've met before.
A special communication-allowance handshake protocol allows them to "learn" how
to talk to each other securely each time they meet in a chat room.

Schnorr Signatures are computed on every transmission and verified by the other
side, both by the sending client and by the server as a mediator, so receivers
can be assured that:

1) The message really did arrive, unaltered, by the receiver's friend.
2) The message really was relayed by the real Rosetta server, unaltered.


