SFTP in Rust
============

This rust crate contains a basic implementation of SFTP in Rust.

It's meant to be used on top of a SSH Channel or a socket to the sftp server. It doesn't contain
a SSH implementation, but will integrate with e.g. a command-line client running "ssh -s $localhost sftp".

The basics of it work. However, it currently doesn't have any tests or much documentation.

It mostly follows the published RFC for version 3, but deviates where other servers and clients
ignore the RFC.

RFC: https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7.8
