# pwsafe-de-dup

This is a toy project to help de-duplicate a Password Safe v3 file.

The de-duplication is for literal complete duplicates.  There's a
situation where the client I use detects a conflict on merging 2
databases, and creates a duplicate record, not realising that that
record already exists in the database.  This means that over time you
end up with lots of duplicates.  It does have ways to clear that up, but
due to laziness and tiny screens I've neglected that, and the problem
has become rampant.  To save myself some time manually deleting them,
I've spent a week writing some code.

This is partly me learning Go, and partly to solve a problem.

This is not a general purpose library for password safe written in Go.  While
writing this I realised why there probably isn't one yet.  It's an old format.

I have not tried to make this secure in the way an app that implements a
password safe program would want.  I am not being careful about wiping memory
for example.

Things I've learnt.

* The password safe v3 file format is old.
* There are examples in lots of languages, due to the age, they may or may not
  work.
* Most of the Perl I came across was so old it didn't work anymore with a more
  modern version of Perl.
* While I could read the C++, in order to confirm things by looking at code
  running under a debugger, I found a python project the simplest to use.

## Building

A Makefile is included to make building simple.  On platforms without make,
just look at the incantations within it.  It's all pretty standard Go
compilation.

Note: the code may have \*nix specific code for console input, so may be
restricted to those platforms.  I haven't checked.

    make

    make lint

## Running

When you run the program it will ask you for the password on the console.

    ./pwsafe db.psafe3 de-dupped.psafe3

## Debugging

If you're using delve to debug this then the password input requires a
tty.  This isn't something you'll get out of the box while running delve on
the console.  To work around that you can use the new `--tty` option.

Use the ptyme program to provide a tty you can link to on one terminal:

    $ target/debug/ptyme
    Opened new PTY device: /dev/pts/6

On another:

    $ dlv debug --tty /dev/pts/6 cli/main.go -- pwsafe.psafe3 de-dupped.psafe3

When the program then interacts with the user, it will be on that first
terminal, and you wil be able to enter the password there.

1. https://github.com/go-delve/delve
1. https://github.com/derekparker/ptyme

## Testing a python library

The Loxodo python project to implenent the pwsafe library was my simlest
gateway into debugging a working parse of a database.

https://www.christoph-sommer.de/loxodo/

With the code for that I was able to play about with it by loading the core
code in the python console, bypassing the UI

    >>> from src.vault import Vault
    >>> v = Vault('test', 'test.psafe3')

I added breakpoints in the code by inserting a line like this so that the code
would stop where I was interested.

    import pdb; pdb.set_trace()
