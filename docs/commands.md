# FastDBG Commands

## break
`^\s*(b|break|B|BREAK)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## break pie
`^\s*(b|break|B|BREAK)\s+(pie|PIE)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## watch
`^\s*(watch)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(1|2|4|8))?(?:\s+(write|read|exec))?$`
## unwatch
`^\s*(unwatch|uwch)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## winfo
`^\s*(winfo|watchinfo)\s*$`
## enable_watch
`^\s*(enable_watch|ewch)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## disable_watch
`^\s*(disable_watch|dwch)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## enable
`^\s*(enable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## disable
`^\s*(disable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## disass
`^\s*(disass)(\s+(0[xx][0-9a-fa-f]+|0[0-7]+|[1-9][0-9]*|0))?(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## stackframe
`^\s*(stackframe|stkf|STACKFRAME|STKF)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## print
`^\s*(p|print|P|PRINT)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## run
`^\s*(r|run|R|RUN)(?:\s+(.+))?$`
## start
`^\s*(s|start|S|START)(?:\s+(.+))?$`
## regs
`^\s*(regs)(?:\s+(.+))?$`
## command
`^\s*(!)(.+)$`
## continue
`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`
## step
`^\s*(step|STEP)\s*$`
## context
`^\s*(context|CONTEXT)\s*$`
## color
`^\s*(color|COLOR)\s*$`
## stack
`^\s*(stack|stk|STACK|STK)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## vmmap
`^\s*(vmmap|VMMAP)(\s+\w+)*\s*$`
## sym
`^\s*(sym|symbol|SYM|SYMBOL)(\s+\w+)*\s*$`
## got
`^\s*(got|GOT)\s*$`
## bins
`^\s*(bins|BINS)\s*$`
## fs_base
`^\s*(fs|fs_base)\s*$`
## visual-heap
`^\s*(vis|visual-heap|VIS|VISUAL-HEAP)\s*$`
## set32
`^\s*(set32)\s+(\S+)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## set16
`^\s*(set16)\s+(\S+)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## set8
`^\s*(set8)\s+(\S+)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## set
`^\s*(set)\s+(\S+)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## xor
`^\s*(xor)\s+(\S+)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`
## telescope
`^\s*(tel|telescope)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## xxd
`^\s*(db|xxd)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## xxd dword
`^\s*(dd|xxd\s+dword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## xxd qword
`^\s*(dq|xxd\s+qword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
## backtrace
`^\s*(bt|backtrace|BT|BACKTRACE)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`
