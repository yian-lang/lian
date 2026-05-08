# A Simple Shell
A shell written in C to help understand processes.

## Features
Has 3 built in commands => [cd, help, exit].\
Also supports redirection and piping.\
So, a command like `ping -c 5 google.com | grep rtt > response.txt` works.
But, multiple pipes are not supported.

## Build
`git clone https://github.com/bsach64/bhshell.git`\
`cd bhshell`\
`make bhshell`\
If you want to run tests\
    `make test`\
`./bhshell`

## TODO
- [x] Understand how creating processes actually works
- [x] Simulate the "|" operator
- [x] Rewrite for better organisation and error handling
    - [x] Rewrite to use xmalloc
    - [x] Add tests
- [x] prompt shows current working directory
- [x] Remove `exit(EXIT_FAILURE)`
- [x] Rewrite the Parser {Basically}
    - [x] Simulate the ">" operator of $BASH
    - [x] Allow for the "|" operator of $BASH
- [ ] Maybe
    - [ ] Support multiple ">" {allowing for `ls > file1.txt > file2.txt`}
    - [ ] Escape characters etc {echo "wow" should print wow instead of "wow"}
    - [ ] Implement some level of globbing (Meaning *.txt means all .txt files in the current dir)
