# Ghidra Extended Parser

[![Build](https://github.com/antoniovazquezblanco/GhidraExtendedSourceParser/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraExtendedSourceParser/actions/workflows/main.yml)

<p align="center">
  <img width="400" src="doc/logo.png" alt="A red dragon reads some source code">
</p>

This is a Ghidra extension that provides some user friendly ways to parse small source code snippets into data types.


## Installing

Go to the [releases page](https://github.com/antoniovazquezblanco/GhidraExtendedSourceParser/releases) and download the latest version for your Ghidra distribution.

In Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.


## Using

There will be a new right click option in the data type manager window to parse data types from C. You can then paste an small snippet of code that will be parsed into types.

![Usage example animation](doc/usage.gif)


## Develop

For development instructions checkout [doc/Develop.md](doc/Develop.md).