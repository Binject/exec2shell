package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"

	"github.com/Binject/debug/elf"
	"github.com/Binject/debug/macho"
	"github.com/Binject/debug/pe"

	"github.com/akamensky/argparse"
)

const (
	// ERROR - constant for an error
	ERROR = iota
	// ELF - constant for ELF binary format
	ELF = iota
	// MACHO - constant for Mach-O binary format
	MACHO = iota
	// FAT - constant for FAT/Mach-O binary format
	FAT = iota
	// PE - constant for PE binary format
	PE = iota
)

func main() {

	parser := argparse.NewParser("exec2shell", "Extracts TEXT section of a PE, ELF, or Mach-O executable to shellcode")
	srcFile := parser.String("i", "in", &argparse.Options{Required: true, Help: "Input PE, ELF, or Mach-o binary"})
	dstFile := parser.String("o", "out", &argparse.Options{Required: false,
		Default: "shellcode.bin", Help: "Output file"})
	if err := parser.Parse(os.Args); err != nil {
		log.Println(parser.Usage(err))
		return
	}

	btype := ERROR
	buf, err := ioutil.ReadFile(*srcFile)
	if err != nil {
		log.Println(err)
		return
	}

	if bytes.Equal(buf[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		btype = ELF
	}
	if bytes.Equal(buf[:3], []byte{0xfe, 0xed, 0xfa}) {
		if buf[3] == 0xce || buf[3] == 0xcf {
			// FE ED FA CE - Mach-O binary (32-bit)
			// FE ED FA CF - Mach-O binary (64-bit)
			btype = MACHO
		}
	}
	if bytes.Equal(buf[1:4], []byte{0xfa, 0xed, 0xfe}) {
		if buf[0] == 0xce || buf[0] == 0xcf {
			// CE FA ED FE - Mach-O binary (reverse byte ordering scheme, 32-bit)
			// CF FA ED FE - Mach-O binary (reverse byte ordering scheme, 64-bit)
			btype = MACHO
		}
	}
	if bytes.Equal(buf[:2], []byte{0x4d, 0x5a}) {
		btype = PE
	}

	if btype == ERROR {
		log.Println("Unknown Binary Format")
		return
	}
	switch btype {
	case ELF:
		elfFile, err := elf.NewFile(bytes.NewReader(buf))
		if err != nil {
			log.Println(err)
			return
		}
		for _, p := range elfFile.Progs {
			if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
				outb := make([]byte, p.Filesz)
				n, err := p.ReaderAt.ReadAt(outb, 0)
				if n != int(p.Filesz) || err != nil {
					log.Println(n, err)
					return
				}
				err = os.WriteFile(*dstFile, outb, 0660)
				if err != nil {
					log.Println(err)
				}
				return
			}
		}
	case MACHO:
		machoFile, err := macho.NewFile(bytes.NewReader(buf))
		if err != nil {
			log.Println(err)
			return
		}
		for _, section := range machoFile.Sections {
			if section.SectionHeader.Seg == "__TEXT" && section.Name == "__text" {
				data, err := section.Data()
				if err != nil {
					log.Println(err)
					return
				}
				err = os.WriteFile(*dstFile, data, 0660)
				if err != nil {
					log.Println(err)
				}
				return
			}
		}
	case PE:
		peFile, err := pe.NewFile(bytes.NewReader(buf))
		if err != nil {
			log.Println(err)
			return
		}
		for _, section := range peFile.Sections {
			flags := section.Characteristics
			if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 { // this section is executable

				data, err := section.Data()
				if err != nil {
					log.Println(err)
					return
				}
				err = os.WriteFile(*dstFile, data, 0660)
				if err != nil {
					log.Println(err)
				}
				return
			}
		}
	}
}
