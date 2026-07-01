#include <Windows.h>
#include "api.h"
#include "resolver.h"
#include "constant.h"
typedef struct BASE_RELOCATION_BLOCK
{
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

PVOID allocate_dll_space(SIZE_T image_size)
{
    if (!image_size || !api)
        return NULL;

    NTSTATUS status = 0;
    // allocate space
    PVOID space = NULL;
    ULONG_PTR zero_bit = 0;
    status = api->FUNCTIONS.NtAllocateVirtualMemory((HANDLE)-1, &space, zero_bit, &image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return NULL;
    }
    if (!space)
        return NULL;
    return space;
}

BOOL resolve_base_relocation(PVOID new_base, PIMAGE_NT_HEADERS nt_header)
{
    if (!new_base || !nt_header)
        return FALSE;
    // handle relocation
    PIMAGE_DATA_DIRECTORY reloc_directory = (PIMAGE_DATA_DIRECTORY)(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    if (!reloc_directory)
        return FALSE;

    if (reloc_directory->Size > 0 && reloc_directory->VirtualAddress)
    {
        PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)new_base + reloc_directory->VirtualAddress); // first block
        if (!base_reloc)
            return FALSE;

        ULONG_PTR delta_address = (ULONG_PTR)new_base - (ULONG_PTR)nt_header->OptionalHeader.ImageBase;
        DWORD byte_steps = 0;
        DWORD size_of_reloc_dir = reloc_directory->Size;

        while (byte_steps < size_of_reloc_dir)
        {
            if (base_reloc->SizeOfBlock == 0)
                break;

            DWORD number_of_block_entry = ((base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY));
            PBASE_RELOCATION_ENTRY block_entry = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)base_reloc + sizeof(IMAGE_BASE_RELOCATION));
            if (!block_entry)
                return FALSE;

            for (DWORD i = 0; i < number_of_block_entry; i++)
            {
                if (block_entry->Type == IMAGE_REL_ALPHA_ABSOLUTE)
                {
                    continue;
                }

                if (block_entry->Type == IMAGE_REL_BASED_DIR64)
                {
                    ULONG_PTR offset_rva = base_reloc->VirtualAddress + block_entry->Offset;
                    ULONG_PTR target_patch = (ULONG_PTR)new_base + offset_rva;
                    if (!target_patch)
                        return FALSE;

                    *(ULONG_PTR *)target_patch += delta_address;
                }

                if (block_entry->Type == IMAGE_REL_BASED_HIGHLOW)
                {
                    ULONG_PTR offset_rva = base_reloc->VirtualAddress + block_entry->Offset;
                    ULONG_PTR target_patch = (ULONG_PTR)new_base + offset_rva;
                    if (!target_patch)
                        return FALSE;
                    *(DWORD *)target_patch += (DWORD)delta_address;
                }
                block_entry++;
            }
            byte_steps += base_reloc->SizeOfBlock;
            base_reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base_reloc + base_reloc->SizeOfBlock);
        }
    }
    return TRUE;
}

BOOL resolve_iat(PVOID new_base, PIMAGE_NT_HEADERS nt_header)
{
    if (!new_base || !nt_header)
        return FALSE;

    PIMAGE_DATA_DIRECTORY import_dir = (PIMAGE_DATA_DIRECTORY)(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (!import_dir)
        return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)new_base + import_dir->VirtualAddress); // first block
    if (!import_descriptor)
        return FALSE;

    while (import_descriptor->Name)
    {
        NTSTATUS status = 0;
        PVOID dll_handle = NULL;
        char *temp_module_name = (char *)((ULONG_PTR)new_base + import_descriptor->Name);
        int i = 0;
        if (temp_module_name)
        {
            STRING module_name;
            RtlInitAnsiString(&module_name, temp_module_name);
            if (!module_name.Buffer)
                return NULL;

            UNICODE_STRING module_name_unicode;
            status = api->FUNCTIONS.RtlAnsiStringToUnicodeString(&module_name_unicode, &module_name, TRUE);

            if (module_name_unicode.Buffer != NULL && NT_SUCCESS(status))
            {
                status = api->FUNCTIONS.LdrLoadDll(NULL, 0, &module_name_unicode, &dll_handle);
            }
        }
        if (!dll_handle || !NT_SUCCESS(status))
            return FALSE;

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)new_base + import_descriptor->FirstThunk);
        if (!thunk)
            return FALSE;

        while (thunk->u1.AddressOfData)
        {
            ULONG function_ordinal = 0;
            STRING function_name;
            PANSI_STRING p_function_name;
            PVOID function_address = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                function_ordinal = (ULONG)IMAGE_ORDINAL(thunk->u1.Ordinal);
                p_function_name = NULL;
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME function = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)new_base + thunk->u1.AddressOfData);
                RtlInitAnsiString(&function_name, function->Name);
                p_function_name = &function_name;
            }

            if ((function_ordinal != 0 || function_name.Buffer != NULL))
            {
                status = api->FUNCTIONS.LdrGetProcedureAddressEx(dll_handle, p_function_name, function_ordinal, &function_address, 0);
                if (!NT_SUCCESS(status))
                {
                    return FALSE;
                }
            }
            if (!function_address)
            {
                thunk->u1.Function = NULL;
            }
            thunk->u1.Function = (ULONG_PTR)function_address;
            thunk++;
        }

        import_descriptor++;
    }
    return TRUE;
}

BOOL resolve_section(PVOID old_base, PVOID new_base, PIMAGE_NT_HEADERS nt_header)
{
    if (!old_base || !new_base || !nt_header)
        return FALSE;

    DWORD number_of_section = 0;
    number_of_section = nt_header->FileHeader.NumberOfSections;
    if (number_of_section > 0)
    {
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(nt_header));
        if (!section)
            return FALSE;

        for (DWORD i = 0; i < number_of_section; i++)
        {
            PVOID new_section = (PVOID)((ULONG_PTR)new_base + section->VirtualAddress);
            if (!new_section)
                return FALSE;

            PVOID section_data = (PVOID)((ULONG_PTR)old_base + section->PointerToRawData);
            if (!section_data)
                return FALSE;

            DWORD section_size = section->SizeOfRawData;
            memcpy_s(new_section, section_size, section_data, section_size);
            section++;
        }
    }
    return TRUE;
}

BOOL reflective_load(PVOID payload_address)
{
    if (!payload_address || !api)
        return FALSE;
    NTSTATUS status = 0;

    PBYTE base_address = (PBYTE)payload_address;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_address;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(base_address + dos->e_lfanew);

    SIZE_T dll_size = nt_header->OptionalHeader.SizeOfImage;
    if (dll_size == 0)
        return FALSE;

    // allocte space
    PVOID new_base = (PBYTE)allocate_dll_space(dll_size);
    if (!new_base)
        return FALSE;

    DWORD header_image_size = nt_header->OptionalHeader.SizeOfHeaders;
    if (!header_image_size)
        return FALSE;

    if (memcpy_s(new_base, dll_size - header_image_size, base_address, header_image_size) != 0)
        return FALSE;

    // copy section to new address
    if (!resolve_section(base_address, new_base, nt_header))
    {
        return FALSE;
    }

    // handle reloc
    if (!resolve_base_relocation(new_base, nt_header))
    {
        return FALSE;
    }
    // handle IAT table
    if (!resolve_iat(new_base, nt_header))
    {
        return FALSE;
    }

    DLLEntry dll_entry = (DLLEntry)((DWORD_PTR)new_base + nt_header->OptionalHeader.AddressOfEntryPoint);
    // PVOID function_address = get_function_address_by_hash(new_base, H_EXPORT_FUNCTION);
    //((void(*)())function_address)();
    if (!dll_entry)
        return FALSE;

    (*dll_entry)((HINSTANCE)new_base, DLL_PROCESS_ATTACH, 0);

    ULONG old_protect = 0;
    status = api->FUNCTIONS.NtProtectVirtualMemory((HANDLE)-1, &new_base, &dll_size, PAGE_EXECUTE_READ, &old_protect);
    return TRUE;
}