# secrets
Golang package to securely save passwords, keys, and other sensitive data.

This package is intended to allow developers to use secure encryption
without having to understand openSSL or cryptography in detail.

It will encrypt and save sensitive data to disk, or load and decrypt
that same sensitive data.  This allows for programs to restart and
access existing sensitive data.  Access to the data is both thread-safe
and safe from corruption when multiple processes access the same secrets
store.

The data in a `secrets.Store` can be put in a password-protected tarball
to be moved to another computer.

# USE

To create a new `secrets.Store`, or open an existing store, a program
calls `store := secrets.NewStore(dirpath string)`. If `dirpath` is an
empty directory, a new store will be created with `dirpath` at the top
level.  If `dirpath` is a directory that contains a `.secretskeys` file,
the existing store at that top-level directory will be opened for use.
If `dirpath` is not an empty directory or if it is not empty and there
is no `dirpath/.secretskeys` directory, an error will be returned.

To encrypt and save sensitive data, call `store.Save(path, data)`.  The
library will encrypt the byte splice `data` and save it in `path` in the
store.  To load and decrypt sensitive data, call `store.Load(path)`
which will return the decrypted data in a byte splice.

# IMPLEMENTATION

Every `secrets.Store` directory contains a `.secretskeys` subdirectory.
In the `.secretskeys` directory, there will be a `secrets.conf` file and
one or more files called `key<N>`.  The key number can be any positive
decimal integer less than 2^64.

The `secrets.conf` file is a YAML file containing:

```
	currentkey: <keynum> (The key to use for newly encrypted data.)
```

Each key file is binary, with the first 4 bytes indicating the
encryption algorithm this key is to use, followed by the key itself
encrypted by the system's TPM2.0 or whatever the most secure method is
to encrypt something that can only be done on that system.

The algorithm matches a hard-coded table of algorithms supported by this
library.  Currently only algorithm 0 is defined, which is AES256.

Everything else in the store directory is encrypted data saved by a user
of this package.  The Save function will call `filepath.Clean(storePath +
"/" + path)` and then confirm that the resulting path starts with
storePath to ensure the caller did not use '..' to get outside the store
directory hierarchy.  The first 8 bytes of the data file is the key
number to use to decrypt this data, followed by the encrypted data
itself.

When NewStore() is called on an empty directory, it will create the
secrets.conf file, setting currentkey to 0, generate key 0, encrypt the
key using the most secure method available on the system, and then save
that in the 'key0' file.

When a store's key needs to be rotated, it calls `store.Rotate()`.  This
will generate a new key, indexed one higher than `currentkey`, saves
that in key<N>, and changes `currentkey` to be the new key in the config
file.  Then it will update all of the store's data to use the new key,
and once all data is confirmed to be encrypted with the new key, all old
keys will be deleted.  If `currentkey` == 2^64-1, `Rotate()` will roll
over and use key '0'.  Probably don't need 64 bits for the key number,
now that I've realized it's not difficult to roll over from 2^N-1 to 0.
Yeah, let's drop it to 1 byte.  256 oughta be more than sufficient for
simultaneous keys.  Need to guarantee it by checking if currentkey+1 has
a file, and if so, return an error on Rotate().
