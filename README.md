CTSync Daemon
=============

[![Build Status](https://travis-ci.org/Censys/ctsync-daemon.svg?branch=master)](https://travis-ci.org/Censys/ctsync-daemon)

Two daemons that synchronize Censys and Certificate Transparency.

## CTSync Pull

`ctsync-pull` monitors CT logs, and adds certificates to Censys.

## CTSync Push

***WARNING: WORK IN PROGRESS, DO NOT USE!**

`ctsync-push` monitors Censys, and logs certificates found in scans to CT.
