# Wingman

Wingman is a cli tool for ad-hoc file backups.
It is designed to be used in pipes and with existing
UNIX shell tools. Furthermore guarding of secret keys
should exist outside wingman itself.

## Quickstart

Wingman requires a 32 byte secret key.
It is read by wingman as 64 char hexstring.
Wingman reads this key by the environment variable
WINGMAN_USER_KEY. With this wingman may be used.

```bash
$ export WINGMAN_USER_KEY=bd6343df2aaf9eb541bee5386787245c7e2a3dd63a02f8029bb0b91ee2b5ef00
$ wingman add /home/bob/file.txt
```

The above command will create the backup directory /tmp/wingman - if we
examine it.

```bash
$ ls /tmp/wingman
salt
b31f872cf65390e924bcfd07f069133837242f3d0d4aa5109842ebb1f606e8ba
```

NOTE: The filename _will_ be different for you.

The directory /tmp/wingman is known as the WINGMAN_ENC_DIR and may
also be set with an environment variable.

```bash
$ export WINGMAN_USER_KEY=bd6343df2aaf9eb541bee5386787245c7e2a3dd63a02f8029bb0b91ee2b5ef00
$ export WINGMAN_ENC_DIR=/home/bob/.wingman
wingman add /home/bob/file.txt
```

The above command will create an encrypted backup of file.txt to the
.wingman directory.

The author envisages WINGMAN_ENC_DIR is a USB stick/network drive etc.
Furthermore it is left to the user to keep WINGMAN_USER_KEY safe,
_somehow_, _somewhere_.


## Usage

This section assumes WINGMAN_ENC_DIR and WINGMAN_SECRET_KEY are
set in the environment.

Wingman has four commands:
	* wingman add
	* wingman ls
	* wingman cat
	* wingman rm


We will add the following file to the encrypted backup.

/home/bob/shopplist
```
garlic
chopped tomatoes
creamed coconut
spinach
rice
Tomato
onion
cauliflower
cinnamon stick
cloves
```

To add the file:

```bash
$ wingman add /home/bob/shopplist
bb32b5e030174886ceb970d2404f314bb9b82d1ca5a02dc1521ba483493c3982
```

We note that the output is a unique id of the created file.
The author envisages wrapping this with a shell script.

To list the file(s):

```bash
$ wingman ls
bb32b5e030174886ceb970d2404f314bb9b82d1ca5a02dc1521ba483493c3982
```

To print the file to the terminal:

```bash
$ wingman cat bb32b5
garlic
chopped tomatoes
creamed coconut
spinach
rice
Tomato
onion
cauliflower
cinnamon stick
cloves
```

We observe that wingman works with only a prefix of the unique id.
An idea taken from git. The prefix must uniquely identify the file
and be of at least length 6.

To grep a file without decrypting it to HDD:

```bash
$ wingman cat bb32b5 | grep onion
onion
```

Wingman can also encrypt data directly from stdin so there's
no need to make a roundtrip to the HDD. This is done with
the special argument - or -0.

```bash
$ echo "hello world" | wingman add -0
aaebfad24039d80443ec2e0c3250f7d7c3042ed21fdf37226c7539a3fcf91d8c
```


## Cookbook

### Encrypting a Directory:

Either zip or tar may be used for this purpose.
To use tar:

```bash
$ tar -c /home/bob/some_directory | wingman add -0
d657288c8c5a9bf836cf2c09ca4d58627fdd3d600f3ce2f331ee7f81d037a003
```

### Zsh tab completion for encrypted files.

TODO.
