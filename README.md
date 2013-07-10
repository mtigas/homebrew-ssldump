# homebrew-ssldump

This repository contains a modified **[ssldump][ssldump]** formula for
[Homebrew][brew], patched to fix support for building with the OpenSSL
Homebrew formula. (ssldump normally compiles with it's own version of 

**You will need to [install Homebrew][brew_install] to use this**, see
[here][brew_install].

[ssldump]: http://www.rtfm.com/ssldump/
[brew]: http://mxcl.github.com/homebrew/
[brew_install]: https://github.com/mxcl/homebrew/wiki/installation

## Usage

There are two methods to install packages from this repository.

### Method 1: Tap

Tap the repository into your brew installation

    brew tap mtigas/ssldump

You'll notice that `brew install ssldump` throws warnings -- this is because
the formula cannot technically replace the original one in Homebrew core.
You can install any of the packages in repo by manually denoting the "tap"
prefix (mtigas/ssldump):

	brew install mtigas/ssldump/ssldump

### Method 2: Raw URL

First, find the raw URL for the formula you want. For example, the raw URL for
the `ssldump` formula is:

    https://github.com/mtigas/homebrew-ssldump/raw/master/Formula/ssldump.rb

Once you know the raw URL, simply use `brew install [raw URL]`, like so:

    brew install https://github.com/mtigas/homebrew-ssldump/raw/master/Formula/ssldump.rb

(Due to dependencies, you may need to perform `brew tap mtigas/ssldump` as in Method 1.)
