**WIP - use at your own risk**
* SF4 compatibility
* OPenSSL Encryption

#DoctrineEncryptBundle

Bundle allows to create doctrine entities with fields that will be protected with 
help of some encryption algorithm in database and it will be clearly for developer, because bundle is uses doctrine life cycle events

###Documentation

The bulk of the documentation is stored in the `Resources/doc/index.md` file in this bundle

The package was originally created by Victor Melnik (@vmelnik-ukraine) and has 
since been extensively modified in the following ways.
* Added proper implementation of AES256
* Added use of prefix to determine when values are encrypted
* Added capability of deterministic values which allow for values to be encrypted with the same IV, which allows the exact values to be searched for.
* Added support for MongoDB.
** Arrays in mongo are encrypted per value and not the whole array.  (Recurses through the arrays)
* Added capability to decrypt values (by adding decrypt to the annotation).
* Encryption implementation is now a service and can be overridden.
* Added command line tool to update an entire database scheme.  This loads and saves every entity/document in the database to update which values are encrypted.

The following documents are available:

* [Configuration reference](https://github.com/TDMobility/DoctrineEncryptBundle/blob/master/Resources/doc/configuration_reference.md)
* [Installation](https://github.com/TDMobility/DoctrineEncryptBundle/blob/master/Resources/doc/installation.md)
* [Example of usage](https://github.com/TDMobility/DoctrineEncryptBundle/blob/master/Resources/doc/example_of_usage.md)

###License

This bundle is under the MIT license. See the complete license in the bundle

###Versions

I'm using Semantic Versioning like described [here](http://semver.org)
