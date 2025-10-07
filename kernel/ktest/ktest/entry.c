/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "tests.h"

#define KTEST				                0x1337
#define KTEST_GET_TEST_ENTRY                CTL_CODE(KTEST, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_SET_TEST_ENTRY                CTL_CODE(KTEST, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_GET_TEST_ENTRY_COUNT          CTL_CODE(KTEST, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_CALL_TEST_ENTRY               CTL_CODE(KTEST, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

VOID     DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
NTSTATUS DriverDeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

ULONG _g_CurrentTestIndex = 0;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
    PTEST_ENTRY pTestEntry = NULL;
	NTSTATUS Status;
	ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&DeviceName, L"\\Device\\KTEST");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\KTEST");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceDispatch;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	
	DriverObject->DriverUnload = DriverUnload;
	Status = IoCreateDevice(DriverObject,
							0,
							&DeviceName,
							FILE_DEVICE_UNKNOWN,
							0,
							FALSE,
							&DeviceObject);
	if (!NT_SUCCESS(Status))
		return Status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	Status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "KTEST Test Driver Loaded.\nHere is a list of callable test entries:\n");

    for (i = 0; i < GetTestEntriesCount(); i++) {
        
        pTestEntry = GetTestEntry(i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "    [%d]  %s (%s) at 0x%p\n", i, pTestEntry->TestName, pTestEntry->TestDescription, pTestEntry->TestFunction);
    }

	return STATUS_SUCCESS;
}


VOID 
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
	UNICODE_STRING Win32Device;
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\KTEST");
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
}


NTSTATUS
DriverCreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS
DriverDefaultHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}


NTSTATUS
DriverDeviceDispatch(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PIO_STACK_LOCATION pIoStackLocation;
	ULONG IoCtlCode;
	ULONG InputBufferLen;
	ULONG OutputBufferLen;
	PUCHAR InputOutputBufferPointer;
    ULONG TestEntryIndex = 0;
    ULONG TestEntrySize = 0;
    ULONG TestEntriesCount = 0;
    PTEST_ENTRY CurrentTestEntry = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(DeviceObject);
    
    TestEntriesCount = GetTestEntriesCount();

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	IoCtlCode		 = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode; 
	OutputBufferLen  = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	InputBufferLen	 = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength; 
	InputOutputBufferPointer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	Irp->IoStatus.Information = 0;
    
	switch (IoCtlCode) {
    
    case KTEST_GET_TEST_ENTRY:
        if (InputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        TestEntryIndex = *((PULONG)InputOutputBufferPointer);
        if (TestEntryIndex >= TestEntriesCount) {

            Status= STATUS_INVALID_PARAMETER;
            break;
        }

        TestEntrySize = GetTestEntrySize();
        if (OutputBufferLen < TestEntrySize) {

            Status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        RtlCopyMemory(InputOutputBufferPointer, GetTestEntry(TestEntryIndex), TestEntrySize);
        Irp->IoStatus.Information = TestEntrySize;
        Status = STATUS_SUCCESS;
		break;

    case KTEST_GET_TEST_ENTRY_COUNT:
        if (OutputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        RtlCopyMemory(InputOutputBufferPointer, &TestEntriesCount, sizeof(ULONG));
        Irp->IoStatus.Information = sizeof(ULONG);
        Status = STATUS_SUCCESS;
		break;

    case KTEST_SET_TEST_ENTRY:
        if (InputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        TestEntryIndex = *((PULONG)InputOutputBufferPointer);
        if (TestEntryIndex >= TestEntriesCount) {

            Status= STATUS_INVALID_PARAMETER;
            break;
        }

        _g_CurrentTestIndex = TestEntryIndex;
        Irp->IoStatus.Information = 0;
        Status = STATUS_SUCCESS;
		break;

    case KTEST_CALL_TEST_ENTRY:
        if (InputBufferLen == 0) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        CurrentTestEntry = GetTestEntry(_g_CurrentTestIndex);
        Status = CurrentTestEntry->TestFunction(InputOutputBufferPointer, InputBufferLen);
        Irp->IoStatus.Information = 0;
		break;

    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[KTEST] Dispatch Routine Received Invalid IO Request...\n");
        break;
	}

    Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}