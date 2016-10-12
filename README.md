# x64dbgida

Official x64dbg plugin for IDA Pro.

## Installation

Copy `x64dbgida.py` to your IDA `plugins` directory.

*Notice*: On older versions of IDA make sure to update IDAPython to the latest release for your IDA version that uses Python 2.7. See [IDAPython RELEASES](https://github.com/idapython/src/tree/build-1.7.2/RELEASES).

## Menu options

### Import (uncompressed) database

Import comments/labels/breakpoints from an uncompressed x64dbg JSON database in IDA Pro.

### Export database

Export comments/labels/breakpoints to a JSON database that can be loaded by x64dbg.
