PVOID load_module_forward(char *forwarder_string)
{
    if (!forwarder_string)
        return NULL;

    const char *dot = strchr(forwarder_string, '.');
    if (!dot)
        return NULL;

    NTSTATUS status = 0;

    // handle load dll
    char temp_module_name[64] = {0};
    size_t module_name_length = dot - forwarder_string;

    strncpy_s(temp_module_name, sizeof(temp_module_name), forwarder_string, module_name_length);

    STRING module_name;
    RtlInitAnsiString(&module_name, temp_module_name);
    if (!module_name.Buffer)
        return NULL;

    UNICODE_STRING module_name_unicode;
    status = api->FUNCTIONS.RtlAnsiStringToUnicodeString(&module_name_unicode, &module_name, TRUE);

    PVOID new_module_base = NULL;
    if (module_name_unicode.Buffer != NULL)
    {
        status = api->FUNCTIONS.LdrLoadDll(NULL, 0, &module_name_unicode, &new_module_base);
    }
    api->FUNCTIONS.RtlFreeUnicodeString(&module_name_unicode);

    if (!NT_SUCCESS(status) || !new_module_base)
        return NULL;

    return new_module_base;
}

PVOID load_function_forward(char *forwarder_string, PVOID module_base)
{
    if (!forwarder_string || !module_base)
        return NULL;

    NTSTATUS status = 0;
    const char *dot = strchr(forwarder_string, '.');
    if (!dot)
        return NULL;

    const char *string_name = NULL;
    PVOID new_function_address = NULL;
    // handle get function address
    ULONG function_ordinal = 0;
    STRING function_name;
    PANSI_STRING p_function_name = NULL;

    if (*(dot + 1) == 0x23)
    { // # get the ordinal number
        const char *ordinal_string = dot + 2;
        status = api->FUNCTIONS.RtlCharToInteger(ordinal_string, 10, &function_ordinal);
        p_function_name = NULL;
    }
    else
    { // get string name
        string_name = dot + 1;
        RtlInitAnsiString(&function_name, string_name);
        p_function_name = &function_name;
    }

    if (NT_SUCCESS(status) && (function_ordinal != 0 || function_name.Buffer != NULL))
    {
        status = api->FUNCTIONS.LdrGetProcedureAddressEx(module_base, p_function_name, function_ordinal, &new_function_address, 0);
    }
    if (NT_SUCCESS(status))
    {
        return new_function_address;
    }
    return NULL;
}

int is_forward_export(PVOID module_base, PVOID function_address)
{
    if (!module_base || !function_address)
        return -1;
    PBYTE base_address = (PBYTE)module_base;

    PIMAGE_DATA_DIRECTORY export_table = get_data_directory(module_base, 0);
    if (!export_table)
        return -1;

    //
    PBYTE start_address = export_table->VirtualAddress + base_address;
    PBYTE end_address = start_address + export_table->Size;

    //
    if ((PBYTE)function_address >= start_address && (PBYTE)function_address <= end_address)
    {
        return 1;
    }
    return 0;
}

PVOID forward_import(PVOID function_address)
{
    if (!function_address)
        return NULL;

    char *forwarder_string = (char *)function_address;
    PVOID new_module_base = NULL;
    PVOID new_function_address = NULL;

    new_module_base = load_module_forward(forwarder_string);
    if (!new_module_base)
        return NULL;

    new_function_address = load_function_forward(forwarder_string, new_module_base);
    if (!new_function_address)
        return NULL;

    return new_function_address;
}

PVOID resolve_import(PCWSTR module_name, DWORD hash_dll, DWORD hash_function)
{
    if (!module_name || !hash_dll || !hash_function)
        return NULL;

    PVOID module_base = get_module_base(hash_dll); // find on RAM first
    if (!module_base && api->FUNCTIONS.LoadLibraryW)
    {
        module_base = (PVOID)api->FUNCTIONS.LoadLibraryW(module_name); // if not found load by LoadLibraryW
    }
    if (!module_base)
        return NULL; // fail if fail to load or LoadLibW not found

    PVOID function_address = get_function_address_by_hash(module_base, hash_function);

    DWORD flag_check = 0;
    flag_check = is_forward_export(module_base, function_address);

    if (flag_check == 1)
    { // if is forward import
        function_address = forward_import(function_address);
    }

    if (function_address && flag_check == 0 || flag_check == 1 && flag_check != -1)
    {
        return function_address;
    }
    return NULL;
}