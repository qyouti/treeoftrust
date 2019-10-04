# treeoftrust
=============

This Java code library is intended to support the work of small teams who use a shared file store for
encrypted files. The intention is to make it impossible for the system administrators of the file
store to read or falsify data in the files. It is out of the scope of the project to prevent
deletion of data by administrators and it assumed that team members will cooperate to prevent 
accidental loss of data and to allow continued access for other team members.

The system will operate as a layer of access control in parallel with the native access control
system of the host file system.

There are several elements to making this work.

* Team members will run trusted software installed on their own computers and secured against tampering.
* The file editing software will be able to stream data to and from files directly encrypted and decrypting as
appropriate.
* Team members will generate their own OpenPGP compatible key pairs and store them securely on their own device.
* Team members will keep a public key ring securely on their own device and will add the public keys of certain other
team members. They will keep a record of the degree of trust they have in those keys.
* Some team members will act as team controllers.
* One or more team controllers will maintain a file on the networked, shared file space which lists team members,
groups and group members. (The Tree of Trust file.) This file will contain signed (and encrypted?) data so its 
authorship can be verified.
* The tree of trust file will state the canonical name of the base folder in the shared file store it applies to. 
* There will be one or more access control files which indicate read and write access permissions to the files. These 
will be digitally signed too.
* Team controllers will periodically scan the file system and edit native access rights to approximate the team
access rights. This will guard against accidental deletion or corruption of files by team members with lower 
access rights.

This Java library will be dependent on the Bouncy Castle Java library.

