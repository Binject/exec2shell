# exec2shell
Extracts TEXT section of a PE, ELF, or Mach-O executable to shellcode


## Installation

## To install to GOPATH/bin:

go install github.com/Binject/exec2shell@latest

## Build from source:

git clone https://github.com/Binject/exec2shell.git

cd exec2shell

go build .


# Usage

exec2shell [-h|--help] -i|--in "<value>" [-o|--out "<value>"]

Arguments:

  -h  --help  Print help information
  
  -i  --in    Input PE, ELF, or Mach-o binary
  
  -o  --out   Output file. Default: shellcode.bin
  
  
# Example
  
exec2shell -i someprog.exe -o shellcode.bin
