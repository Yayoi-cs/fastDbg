# fastDbg - super fast x64 elf debugger with golang -

Author: github.com/Yayoi-cs (tsune)

## Install

```bash
$ git clone https://github.com/Yayoi-cs/fastDbg.git
$ cd fastDbg
$ git clone https://github.com/capstone-engine/capstone.git
# Build capstone at first
$ go build
```

## Run

sudo is required for attaching

```bash
[~/GolandProjects/fastDbg]$./fastDbg 
      ___           ___           ___           ___           ___           ___           ___
     /\  \         /\  \         /\  \         /\  \         /\  \         /\  \         /\  \
    /::\  \       /::\  \       /::\  \        \:\  \       /::\  \       /::\  \       /::\  \
   /:/\:\  \     /:/\:\  \     /:/\ \  \        \:\  \     /:/\:\  \     /:/\:\  \     /:/\:\  \
  /::\~\:\  \   /::\~\:\  \   _\:\~\ \  \       /::\  \   /:/  \:\__\   /::\~\:\__\   /:/  \:\  \
 /:/\:\ \:\__\ /:/\:\ \:\__\ /\ \:\ \ \__\     /:/\:\__\ /:/__/ \:|__| /:/\:\ \:|__| /:/__/_\:\__\
 \/__\:\ \/__/ \/__\:\/:/  / \:\ \:\ \/__/    /:/  \/__/ \:\  \ /:/  / \:\~\:\/:/  / \:\  /\ \/__/
      \:\__\        \::/  /   \:\ \:\__\     /:/  /       \:\  /:/  /   \:\ \::/  /   \:\ \:\__\
       \/__/        /:/  /     \:\/:/  /     \/__/         \:\/:/  /     \:\/:/  /     \:\/:/  /
                   /:/  /       \::/  /                     \::/__/       \::/__/       \::/  /
                   \/__/         \/__/                       ~~            ~~            \/__/
Invalid arguments
Usage: ./fastDbg [OPTIONS] <file>

Options:
  -f string
        filename
  -p int
        process id
```

## Commands

