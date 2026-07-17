# PE Parser

A Portable Executable (PE) parser written in C for Windows. This project demonstrates the fundamentals of parsing Windows PE files by reading the executable into memory and extracting information from its internal structures.

The parser validates the DOS and NT headers before displaying information about the executable and its section table.

## Features

- Reads a PE file directly into memory
- Validates the DOS (`MZ`) signature
- Validates the NT (`PE`) signature
- Parses the DOS Header
- Parses the NT Headers
- Displays File Header information
- Displays Optional Header information
- Lists all section headers
- Performs basic boundary validation to prevent invalid header access

## Project Structure

```
PE-Parser/
│── main.c
│── README.md
```

## How It Works

The parser performs the following steps:

1. Opens the specified executable file.
2. Reads the entire file into a memory buffer.
3. Validates the DOS Header (`IMAGE_DOS_HEADER`).
4. Uses `e_lfanew` to locate the NT Headers.
5. Validates the NT Signature (`IMAGE_NT_HEADERS`).
6. Extracts information from:
   - DOS Header
   - File Header
   - Optional Header
7. Iterates through the Section Table and prints information about every section.

## Information Extracted

### DOS Header

- DOS Signature (`MZ`)
- Offset to NT Headers (`e_lfanew`)

### File Header

- Machine Type
- Number of Sections
- TimeDateStamp
- Size of Optional Header

### Optional Header

- Entry Point
- Image Base
- Section Alignment
- File Alignment
- Size of Image
- Size of Headers
- Number of Data Directories

### Section Headers

For every section:

- Section Name
- Virtual Address
- Virtual Size
- Raw Data Address
- Raw Data Size

Example output:

```
[+] Sections (5):

    Name     VirtAddr   VirtSize   RawAddr    RawSize
    ----     --------   --------   -------    -------
    .text    0x1000     0x4F200    0x400      0x4F400
    .rdata   0x51000    0x16C00    0x4F800    0x16E00
    .data    0x68000    0x1200     0x66600    0x400
    .pdata   0x6A000    0x2C00     0x66A00    0x2E00
    .rsrc    0x6D000    0x18000    0x69800    0x18200
```

## Building

### Using GCC (MinGW)

```bash
gcc main.c -o PEParser.exe
```

### Using Microsoft Visual Studio

```bat
cl main.c
```

## Usage

```bash
Parser.exe <path_to_pe_file>
```

Example:

```bash
Parser.exe C:\Windows\System32\notepad.exe
```

## Example Output

```
[+] DOS Header:
    e_magic:    0x5A4D (MZ)
    e_lfanew:   0xF8

[+] NT Headers:
    Signature: 0x4550 (PE)

[+] File Header:
    Machine:              0x8664
    NumberOfSections:     5
    TimeDateStamp:        0x6824D95B
    SizeOfOptionalHeader: 0xF0

[+] Optional Header:
    AddressOfEntryPoint:  0x1000
    ImageBase:            0x140000000
    SectionAlignment:     0x1000
    FileAlignment:        0x200
    SizeOfImage:          0x70000
    SizeOfHeaders:        0x400
    NumberOfRvaAndSizes:  16

[+] Sections (5):
    ...
```

## Technologies

- C
- Windows API (`windows.h`)
- Portable Executable (PE) Format

## Error Handling

The parser checks for:

- File not found
- Failed memory allocation
- Read failures
- Invalid DOS signature
- Invalid NT signature
- Invalid NT header offset
- Files that are too small to contain valid PE headers

```