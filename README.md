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

exec2shell        [-h|--help] -i|--in "<value>" [-o|--out "<value>"]
                  [-c|--c-outfile "<value>"] [-n|--c-var "<value>"]
                  [-g|--go-outfile "<value>"] [-p|--go-pkg "<value>"]
                  [-v|--go-var "<value>"]

Arguments:

  **-h**    --help        Print help information
  
  **-i**    --in          Input PE, ELF, or Mach-o binary
  
  **-o**    --out         Output file - Shellcode as Binary. Default: shellcode.bin
  
  **-c**    --c-outfile   Output file - Shellcode as C Array
  
  **-n**    --c-var       Sets variable name for C Array output. Default: SHELLCODE
  
  **-g**   --go-outfile   Output file - Shellcode as Go Array
  
  **-p**    --go-pkg      Sets package string for Go Array output. Default: shellcode
  
  **-v**    --go-var      Sets variable name for Go Array output. Default: shellcode
  
  
# Examples
  
### Make shellcode from a binary:

exec2shell -i someprog.exe -o shellcode.bin

### Make a C-Array style header file shellcode:

exec2shell -i someprog.exe -c shellcode.h -n SHELLCODE_VARNAME

### Make a Go-Array style shellcode

exec2shell -i someprog.exe -g shellcode.go -p mypackage -v DONUT

### Make All the Things at Once:

exec2shell -i someprog.exe -o shellcode.bin -c shellcode.h -g shellcode.go -p mypackage -n C_VARNAME -v GO_VARNAME
