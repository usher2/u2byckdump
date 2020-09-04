Parse and serve fresh Belarusian dump of restricted sites
=========================================================

* Use https://github.com/usher2/dump-by-upload as dump sources server
* Unsigned Belarusian dumps in the `res` folder for test purpose (git lfs)

IMPORTANT NOTE
--------------

This program is a part of [Usher2](https://usher2.club) ecosystem. The gRPC service will never be published

USE
---

* First the program tries to parse a dump.xml file if it exists
* Then the program periodically tries to fetch a dump from a dump sources server

FEATURES
-------

* Native IPv4 string to 32-bit integer implementation
* gRPC service for check IPv4, URL, Domain

WARNING
-------

* Stream parsing a `<resource>...</resource>` object is not a good idea. Because we need some checksum on updates before data applying. So I use `Decode()` method for `<resource>...</resource>` parsing
* I don't trust to any data. I'm not trying to guess unknown errors. Only known patterns. Belarusian officials are such entertainers

TODO
----

* Native RFC3339 parsing
* ~~gRPC service for check IPv4, URL, Domain~~
* Stream parsing every `<resource>...</resource>` object including unchanged is the subject for discussion

---
[![UNLICENSE](noc.png)](UNLICENSE)
