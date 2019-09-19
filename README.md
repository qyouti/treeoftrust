# treeoftrust
This library supports the use of a public key collection, in OpenPGP format, to define a tree of truest.  This is a similar concept to the OpenPGP web of trust, backed by a key database.
The difference is that a simple file hosted on shared file space is used for the implementation so no server side software is needed.  It also restricts the trust relationships to
a simple tree model to make it simpler for users to understand.  The code library will supply an API for editing and maintaining the public key collection including some Swing components that can be 
used in GUI applications.

This Java library will be dependent on the Bouncy Castle Java library.

