#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

BYTE * ReadFileToBuffer(const char *path, long *fileSize)
{
    FILE * fptr = fopen(path, "rb");
    if (fptr == NULL)
    {
        printf("File not found!\n");
        return NULL;
    }

    fseek(fptr, 0, SEEK_END);
    long size = ftell(fptr);

    if (size < 0)
    {
        fclose(fptr);
        return NULL;
    }

    rewind(fptr);
    BYTE *buffer = malloc((size_t)size);

    if (buffer == NULL)
    {
        fclose(fptr);
        return NULL;
    }

    size_t bytesRead = fread(buffer, 1, (size_t)size, fptr);

    if (bytesRead != (size_t)size)
    {
        printf("Error reading file.\n");
        free(buffer);
        fclose(fptr);
        return NULL;
    }
    fclose(fptr);
    *fileSize = size;
    return buffer;
}
void ParseDosHeaders(BYTE * buffer,long filesize){
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (filesize < sizeof(IMAGE_DOS_HEADER))
    {
        printf("File is too small,\n");
        return;
    }
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS Signature , Not a PE file.\n");
        return;
    }
    printf("[+] DOS Header:\n");
	printf("    e_magic:    0x%X (MZ)\n", DosHeader->e_magic); 
	printf("    e_lfanew:   0x%X (Offset to NT Headers)\n", DosHeader->e_lfanew);
}
void ParseNTHeaders(BYTE * buffer,long filesize){
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(buffer+DosHeader->e_lfanew);
    if (DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > filesize)
    {
        printf("Invalid NT header offset.\n");
        return;
    }
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT Signature , Not a PE file.\n");
        return;
    }
    printf("[+] NT Headers:\n");
	printf("    Signature:  0x%X (PE)\n", NtHeaders->Signature);

    printf("[+] File Header:\n"); 
	printf("    Machine:              0x%X\n", NtHeaders->FileHeader.Machine); 
	printf("    NumberOfSections:     %d\n", NtHeaders->FileHeader.NumberOfSections); 
	printf("    TimeDateStamp:        0x%X\n", NtHeaders->FileHeader.TimeDateStamp); 
	printf("    SizeOfOptionalHeader: 0x%X\n", NtHeaders->FileHeader.SizeOfOptionalHeader);

    printf("[+] Optional Header:\n"); 
	printf("    AddressOfEntryPoint:  0x%X\n", NtHeaders->OptionalHeader.AddressOfEntryPoint); 
	printf("    ImageBase:            0x%X\n",NtHeaders->OptionalHeader.ImageBase);
	printf("    SectionAlignment:     0x%X\n", NtHeaders->OptionalHeader.SectionAlignment);
	printf("    FileAlignment:        0x%X\n", NtHeaders->OptionalHeader.FileAlignment); 
	printf("    SizeOfImage:          0x%X\n", NtHeaders->OptionalHeader.SizeOfImage); 
	printf("    SizeOfHeaders:        0x%X\n", NtHeaders->OptionalHeader.SizeOfHeaders); 
	printf("    NumberOfRvaAndSizes:  %d\n", NtHeaders->OptionalHeader.NumberOfRvaAndSizes);
}
void ParseSectionHeaders(BYTE * buffer){
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(buffer+DosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
    WORD numsections = NtHeaders->FileHeader.NumberOfSections;

    printf("[+] Sections (%d):\n", numsections);
    printf("    %-8s %-10s %-10s %-10s %-10s\n","Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize");
	printf("    %-8s %-10s %-10s %-10s %-10s\n","----", "--------", "--------", "-------", "-------");
    for (WORD i = 0; i < numsections; i++)
    {
        printf("    %-8.8s 0x%-8X 0x%-8X 0x%-8X 0x%-8X\n",
                SectionHeaders[i].Name,
                SectionHeaders[i].VirtualAddress,
                SectionHeaders[i].Misc.VirtualSize,
                SectionHeaders[i].PointerToRawData,
                SectionHeaders[i].SizeOfRawData);
    }
    
}
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <PE file>\n", argv[0]);
        return 1;
    }
    long fileSize;
    BYTE * buffer = ReadFileToBuffer(argv[1], &fileSize);
    if (buffer == NULL)
    {
        return 1;
    }
    ParseDosHeaders(buffer,fileSize);
    ParseNTHeaders(buffer, fileSize);
    ParseSectionHeaders(buffer);    
    free(buffer);
    return 0;
}