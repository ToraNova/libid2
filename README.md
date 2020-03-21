# Autotools C/C++ Template
This directory acts as a template to start a Autotool project.
The language this template supports are C and C++.

This template is created following this [tutorial](https://www.lrde.epita.fr/~adl/dl/autotools.pdf)

### Notes
Generate autotool files using `autoreconf --install`

set installation prefix to $HOME/test with `./configure --prefix ~/test`

alternatively, one could do mkdir build && cd build && ../configure to build inside a clean directory.

the default template does not come with the right autofiles. once `autoreconf --install` is run, and you would like to revert, use git instead.
```
git clean -df
git checkout -- .
```
