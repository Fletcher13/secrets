
# secrets

Golang package to securely save passwords, keys, and other sensitive data.

This package is intended to allow developers to use secure encryption
without having to understand cryptography in detail.

It will encrypt and save sensitive data to disk, or load and decrypt
that same sensitive data.  This allows for programs to restart and
access existing sensitive data.  Access to the data is both thread-safe
and safe from corruption when multiple processes access the same
secrets.

The data in a `secrets.Store` can be put in a password-protected tarball
to be copied to another computer.

# USE

To create a new `secrets.Store`, or open an existing store, a program
calls `store := secrets.NewStore(dirpath string, key []byte)`. If
`dirpath` is an empty directory, a new store will be created with
`dirpath` at the top level.  If `dirpath` is a directory that contains a
`.secretskeys` file, the existing store at that top-level directory will
be opened for use.  If `dirpath` is not an empty directory or if it is
not empty and there is no `dirpath/.secretskeys` directory, an error
will be returned.

The `key` passed in to `NewStore()` is used to decrypt the keys in the
`.secrets.keys` directory.  Need to determine how to do the encryption,
whether it's PBKDF2 or AES256GCM or some other way that allows any byte
length to be used as the key/password.

To encrypt and save sensitive data, call `store.Save(path, data)`.  The
library will encrypt the byte splice `data` and save it in `path` in the
store.  To load and decrypt sensitive data, call `store.Load(path)`
which will return the decrypted data in a byte splice.

# IMPLEMENTATION

Every `secrets.Store` directory contains a `.secretskeys` subdirectory.
In the `.secretskeys` directory, there will be a `currentkey` file and
one or more files called `key<N>`.  The key number can be any number
between 0 and 255.

The `currentkey` file will always be a single byte indicating which key
number is the key to use for newly encrypted data.

Each key file is binary, with the first byte indicating the encryption
algorithm this key is to use, followed by the key itself encrypted by
TPM2.0 or whatever the most secure method is to encrypt something on
that system.  The last resort is an unencrypted "unit key" that never
leaves that system, but some better means of protecting the store keys
really should be found.  Maybe `NewStore()` has to be given the "unit
key" in the function call, and the user of the library is responsible
for keeping the unitkey secure.

The algorithm matches a hard-coded table of algorithms supported by this
library.  Currently only algorithm 0 is defined, which is AES256GCM.

Everything else in the store directory is encrypted data saved by a user
of this package.  The Save function will call `filepath.Clean(storePath
+ "/" + path)` and then confirm that the resulting path starts with
storePath to ensure the caller did not use '..' to get outside the store
directory hierarchy.  The first byte of the data file is the key
number to use to decrypt this data, followed by the encrypted data
itself.

When NewStore() is called on an empty directory, it will create the
currentkey file, set currentkey to 0, generate, encrypt, and save key 0.

When a store's key needs to be rotated, `store.Rotate()` is called.
This will generate a new key, indexed one higher than `currentkey`,
saves that in key<N>, and changes `currentkey` to be the new key in the
config file.  Then it will update all of the store's data to use the new
key, and once all data is confirmed to be encrypted with the new key,
all old keys will be deleted.  If `currentkey` == 255, `Rotate()` will
roll over and use key '0'.  Rotate() checks if currentkey+1 has a file,
and if so, return an error.

File rwlocks locks must be used to make this library threadsafe and
process-safe.  Would be great if it could be made multi-computer safe
for NFS filesystems, but will need to research flock on NFS to see if
that can work.

When `NewStore()` is called, it will check that there is a keyfile for
currentkey and return an error if there isn't, and will also check if
there is more than one keyfile.  If there are multiple key files,
`NewStore()` will start a goroutine which will walk through the entire
store file heirarchy and every key not encrypted by currentkey will be
re-encrypted with currentkey.  Once that process is done, it will delete
all old keys.  Except that something needs to handle someone calling
Rotate while a walkthru is happening so that the goroutine walking
through the directory tree will know to just stop.  I think if it sets
an inotify on the config file and exits the goroutine when the
config file changes that would be sufficient.  Whatever changed
currentkey is now responsible for updating the secrets to use the new
key.  Need to think a while about how to handle multiple goroutines
trying to update the secrets simultaneously.  The problem is that if a
rotation is started and the program or computer crashes during the
re-encryption process, then some secrets will be using the new key and
others will be using the old key.  So, when the next program comes along
to access the keystore, it needs to restart that process of
re-encryption.  But, the re-encryption has to be happening as its own
goroutine and not block the main flow of any program using this library.

The other thing that can happen is Rotate() can be called while a
previous rotate is still updating the secrets.  In this case, the
previous secret update goroutine(s) should be stopped and the new one
starts updating all over again.