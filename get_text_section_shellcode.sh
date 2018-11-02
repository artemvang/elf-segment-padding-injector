#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: ./get_text_section_shellcode <elf_file>"
    exit 1
fi

objcopy -O binary --only-section=.text $1 /tmp/payload_text
hexdump -v -e '"\\" 1/1 "x%02x"' /tmp/payload_text; echo
rm /tmp/payload_text
