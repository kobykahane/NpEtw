#include "NpEtw.h"

extern "C" {

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, NpEtwUnload)
#pragma alloc_text(PAGE, NpEtwInstanceQueryTeardown)
#pragma alloc_text(PAGE, NpEtwInstanceSetup)
#pragma alloc_text(PAGE, NpEtwPreCreateNamedPipe)
#pragma alloc_text(PAGE, NpEtwPostCreateNamedPipe)
#pragma alloc_text(PAGE, NpEtwPostReadWhenSafe)
#pragma alloc_text(PAGE, NpEtwPostWriteWhenSafe)
#endif

PFLT_FILTER gFilterHandle = nullptr;

__declspec(allocate("INIT")) CONST FLT_OPERATION_REGISTRATION OperationCallbacks[] = {
    { IRP_MJ_CREATE,              0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_CREATE_NAMED_PIPE,   0, NpEtwPreCreateNamedPipe, NpEtwPostCreateNamedPipe },
    { IRP_MJ_CLOSE,               0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_READ,                0, nullptr,	              NpEtwPostRead            },
    { IRP_MJ_WRITE,               0, nullptr,                 NpEtwPostWrite           },
    { IRP_MJ_QUERY_INFORMATION,   0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_SET_INFORMATION,     0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_FLUSH_BUFFERS,       0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_DIRECTORY_CONTROL,   0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_CLEANUP,             0, NpEtwPreOperation,       NpEtwPostOperation       },
//  { IRP_MJ_CREATE_MAILSLOT,     0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_QUERY_SECURITY,      0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_SET_SECURITY,        0, NpEtwPreOperation,       NpEtwPostOperation       },
    { IRP_MJ_OPERATION_END }
};

__declspec(allocate("INIT")) CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),             // Size
    FLT_REGISTRATION_VERSION,             // Version
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS, // Flags
    nullptr,                              // Context registration
    OperationCallbacks,                   // Operation callbacks
    NpEtwUnload,                          // FilterUnload
    NpEtwInstanceSetup,                   // InstanceSetup
    NpEtwInstanceQueryTeardown,           // InstanceQueryTeardown
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	__try {
		status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
		if (!NT_SUCCESS(status)) {
			__leave;
		}

		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status)) {
			__leave;
		}
	} __finally {
		if (!NT_SUCCESS(status)) {
			if (gFilterHandle) {
				FltUnregisterFilter(gFilterHandle);
			}
		}
	}

	return status;
}

NTSTATUS FLTAPI NpEtwUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}

NTSTATUS FLTAPI NpEtwInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

	if (VolumeFilesystemType == FLT_FSTYPE_NPFS) {
		return STATUS_SUCCESS;
	} else {
		return STATUS_FLT_DO_NOT_ATTACH;
	}
}

NTSTATUS FLTAPI NpEtwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI NpEtwPreCreateNamedPipe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
	)
{	
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	PFLT_FILE_NAME_INFORMATION fileNameInfo = nullptr;
	__try {
		// Get the pipe's name in the Filter Manager's cache here in pre-create when it is cheapest (can be picked up from FileObject->FileName).
		NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Error 0x%08x retrieving pipe name in pre-create pipe.\n", status));
			__leave;
		}
	} __finally {
		if (fileNameInfo) {
			FltReleaseFileNameInformation(fileNameInfo);
		}
	}

	return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostCreateNamedPipe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PFLT_FILE_NAME_INFORMATION fileNameInfo = nullptr;
	__try {
		// We expect this to hit the cache.
		NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Error 0x%08x retrieving pipe name in post create pipe.\n", status));
			__leave;
		}

		status = FltParseFileNameInformation(fileNameInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Error 0x%08x parsing pipe name in post create pipe.\n", status));
			__leave;
		}

		auto& createPipeParameters = Data->Iopb->Parameters.CreatePipe;
		auto namedPipeCreateParameters = static_cast<PNAMED_PIPE_CREATE_PARAMETERS>(createPipeParameters.Parameters);

		KdPrint(("IRP_MJ_CREATE_NAMED_PIPE\n"));
		KdPrint(("\tIoStatus 0x%08x\n", Data->IoStatus.Status));
		KdPrint(("\tFileObject 0x%p\n", FltObjects->FileObject));
		KdPrint(("\tFileName %wZ\n", &fileNameInfo->Name));
		KdPrint(("\tCreateOptions 0x%08x\n", createPipeParameters.Options));
		KdPrint(("\tShareAccess 0x%08x\n", createPipeParameters.ShareAccess));
		KdPrint(("\tIssuingThreadId 0x%p\n", PsGetThreadId(Data->Thread)));
		KdPrint(("\tNamedPipeType 0x%08lx\n", namedPipeCreateParameters->NamedPipeType));
		KdPrint(("\tReadMode 0x%08lx\n", namedPipeCreateParameters->ReadMode));
		KdPrint(("\tCompletionMode 0x%08lx\n", namedPipeCreateParameters->CompletionMode));
		KdPrint(("\tMaximumInstances 0x%08lx\n", namedPipeCreateParameters->MaximumInstances));
		KdPrint(("\tInboundQuota 0x%08lx\n", namedPipeCreateParameters->InboundQuota));
		KdPrint(("\tOutboundQuota 0x%08lx\n", namedPipeCreateParameters->OutboundQuota));
		if (namedPipeCreateParameters->TimeoutSpecified) {
			KdPrint(("\tDefaultTimeout 0x%I64x\n", namedPipeCreateParameters->DefaultTimeout.QuadPart));
		}
		KdPrint(("\tTimeoutSpecified %d\n", namedPipeCreateParameters->TimeoutSpecified));
	} __finally {
		if (fileNameInfo) {
			FltReleaseFileNameInformation(fileNameInfo);
		}
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	FLT_POSTOP_CALLBACK_STATUS postOperationStatus = FLT_POSTOP_FINISHED_PROCESSING;

	if (NT_SUCCESS(Data->IoStatus.Status)) {
		if (!FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, NpEtwPostReadWhenSafe, &postOperationStatus)) {
			KdPrint(("Posting pipe read completion failed.\n"));
		}
	} else {
		KdPrint(("Pipe read failed with status 0x%08x,\n", Data->IoStatus.Status));
	}

	return postOperationStatus;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostReadWhenSafe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	__try {
		if (Data->IoStatus.Information == 0) {
			__leave;
		}

		NTSTATUS status = FltLockUserBuffer(Data);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Error 0x%08x locking user buffer in post-read\n", status));
			__leave;
		}

		__try {
			auto& readParams = Data->Iopb->Parameters.Read;

			PCHAR readBuffer = static_cast<PCHAR>(MmGetSystemAddressForMdlSafe(readParams.MdlAddress, LowPagePriority));
			if (!readBuffer) {
				__leave;
			}

			KdPrint(("Pipe read data: "));
			for (ULONG_PTR i = 0; i < Data->IoStatus.Information; ++i) {
				KdPrint(("%02x", readBuffer[i]));
			}
			KdPrint(("\n"));
		} __except (FsRtlIsNtstatusExpected(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			KdPrint(("Error 0x%08x accessing user buffer in post-read\n", GetExceptionCode()));
		}
	} __finally {

	}
	
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	FLT_POSTOP_CALLBACK_STATUS postOperationStatus = FLT_POSTOP_FINISHED_PROCESSING;

	if (NT_SUCCESS(Data->IoStatus.Status)) {
		if (!FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, NpEtwPostWriteWhenSafe, &postOperationStatus)) {
			KdPrint(("Posting pipe write completion failed.\n"));
		}
	} else {
		KdPrint(("Pipe write failed with status 0x%08x\n", Data->IoStatus.Status));
	}

	return postOperationStatus;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostWriteWhenSafe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	__try {
		if (Data->IoStatus.Information == 0) {
			__leave;
		}

		NTSTATUS status = FltLockUserBuffer(Data);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Error 0x%08x locking user buffer in post-write\n"));
			__leave;
		}

		__try {
			auto& writeParams = Data->Iopb->Parameters.Write;

			PCHAR writeBuffer = static_cast<PCHAR>(MmGetSystemAddressForMdlSafe(writeParams.MdlAddress, LowPagePriority));
			if (!writeBuffer) {
				__leave;
			}

			KdPrint(("Pipe write data: "));
			for (ULONG_PTR i = 0; i < Data->IoStatus.Information; ++i) {
				KdPrint(("%02x", writeBuffer[i]));
			}
			KdPrint(("\n"));
		} __except (FsRtlIsNtstatusExpected(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
		{
			KdPrint(("Error 0x%08x accessing user buffer in post-write\n", GetExceptionCode()));
		}
	} __finally {

	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI NpEtwPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

} // extern "C"
