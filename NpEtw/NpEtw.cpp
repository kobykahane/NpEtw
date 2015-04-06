#include "NpEtw.h"
#include "NpEtw.tmh"

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
PDRIVER_OBJECT gDriverObject = nullptr;

__declspec(allocate("INIT")) CONST FLT_OPERATION_REGISTRATION OperationCallbacks[] = {
    { IRP_MJ_CREATE,              0, NpEtwPreCreateNamedPipe, NpEtwPostCreateNamedPipe },
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
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    NpEtwTraceFuncEntry(General, TRACE_LEVEL_VERBOSE);

    gDriverObject = DriverObject;

	NTSTATUS status = STATUS_SUCCESS;
	__try {
		status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
		if (!NT_SUCCESS(status)) {
            NpEtwTraceError(General, "FltRegisterFilter failed with status %!STATUS!", status);
			__leave;
		}

		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status)) {
            NpEtwTraceError(General, "FltStartFiltering failed with status %!STATUS!", status);
			__leave;
		}
	} __finally {
		if (!NT_SUCCESS(status)) {
			if (gFilterHandle) {
				FltUnregisterFilter(gFilterHandle);
			}

            WPP_CLEANUP(DriverObject);
		}
	}

    NpEtwTraceFuncExit(General, TRACE_LEVEL_VERBOSE);

    return status;
}

NTSTATUS FLTAPI NpEtwUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

    NpEtwTraceFuncEntry(General, TRACE_LEVEL_VERBOSE);

	FltUnregisterFilter(gFilterHandle);

    NpEtwTraceFuncExit(General, TRACE_LEVEL_VERBOSE);

    WPP_CLEANUP(gDriverObject);

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

    PAGED_CODE();

    NpEtwTraceFuncEntry(General, TRACE_LEVEL_VERBOSE);

    NTSTATUS status;

	if (VolumeFilesystemType == FLT_FSTYPE_NPFS) {
		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FLT_DO_NOT_ATTACH;
	}

    NpEtwTraceFuncExit(General, TRACE_LEVEL_VERBOSE);

    return status;
}

NTSTATUS FLTAPI NpEtwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    NpEtwTraceFuncEntry(General, TRACE_LEVEL_VERBOSE);

    NpEtwTraceFuncExit(General, TRACE_LEVEL_VERBOSE);

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

    NpEtwTraceFuncEntry(Create, TRACE_LEVEL_RESERVED6);

	PFLT_FILE_NAME_INFORMATION fileNameInfo = nullptr;
	__try {
		// Get the pipe's name in the Filter Manager's cache here in pre-create when it is cheapest (can be picked up from FileObject->FileName).
		NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
		if (!NT_SUCCESS(status)) {
            NpEtwTraceError(Create, "Retreiving pipe name in pre-create/createnp failed with status %!STATUS!", status);
			__leave;
		}
	} __finally {
		if (fileNameInfo) {
			FltReleaseFileNameInformation(fileNameInfo);
		}
	}

    NpEtwTraceFuncExit(Create, TRACE_LEVEL_RESERVED6);

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

    NpEtwTraceFuncEntry(Create, TRACE_LEVEL_RESERVED6);

	
	__try {
        NpEtwTraceInfo(Create, "%s Cbd 0x%p FileObject 0x%p IoStatus %!STATUS!", 
            FltGetIrpName(Data->Iopb->MajorFunction), FltObjects->FileObject, Data, Data->IoStatus.Status);

        if (NT_SUCCESS(Data->IoStatus.Status)) {
            PFLT_FILE_NAME_INFORMATION fileNameInfo = nullptr;
            __try {
                // We expect this to hit the cache.
                NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
                if (!NT_SUCCESS(status)) {
                    NpEtwTraceError(Create, "Retrieving pipe name in post-create/createnp failed with status %!STATUS!", status);
                    __leave;
                }

                status = FltParseFileNameInformation(fileNameInfo);
                if (!NT_SUCCESS(status)) {
                    NpEtwTraceError(Create, "Parsing pipe name in post-create/createnp failed with status %!STATUS!", status);
                    __leave;
                }

                NpEtwTraceInfo(Create, "\tFileName %wZ", &fileNameInfo->Name);
            } __finally {
                if (fileNameInfo) {
                    FltReleaseFileNameInformation(fileNameInfo);
                }
            }
        }
        
        if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_NAMED_PIPE) {
            auto& createPipeParameters = Data->Iopb->Parameters.CreatePipe;
            auto namedPipeCreateParameters = static_cast<PNAMED_PIPE_CREATE_PARAMETERS>(createPipeParameters.Parameters);


            NpEtwTraceInfo(Create, "\tCreateOptions 0x%08x", createPipeParameters.Options);
            NpEtwTraceInfo(Create, "\tShareAccess 0x%04hx", createPipeParameters.ShareAccess);
            NpEtwTraceInfo(Create, "\tIssuingThreadId 0x%p", PsGetThreadId(Data->Thread));
            NpEtwTraceInfo(Create, "\tNamedPipeType 0x%08lx", namedPipeCreateParameters->NamedPipeType);
            NpEtwTraceInfo(Create, "\tReadMode 0x%08lx", namedPipeCreateParameters->ReadMode);
            NpEtwTraceInfo(Create, "\tCompletionMode 0x%08lx", namedPipeCreateParameters->CompletionMode);
            NpEtwTraceInfo(Create, "\tMaximumInstances 0x%08lx", namedPipeCreateParameters->MaximumInstances);
            NpEtwTraceInfo(Create, "\tInboundQuota 0x%08lx", namedPipeCreateParameters->InboundQuota);
            NpEtwTraceInfo(Create, "\tOutboundQuota 0x%08lx\n", namedPipeCreateParameters->OutboundQuota);
            if (namedPipeCreateParameters->TimeoutSpecified) {
                NpEtwTraceInfo(Create, "\tDefaultTimeout 0x%llx", namedPipeCreateParameters->DefaultTimeout.QuadPart);
            }
            NpEtwTraceInfo(Create, "\tTimeoutSpecified %d", namedPipeCreateParameters->TimeoutSpecified);
        } else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
            auto& createParameters = Data->Iopb->Parameters.Create;

            NpEtwTraceInfo(Create, "\tCreateOptions 0x%08x", createParameters.Options);
            NpEtwTraceInfo(Create, "\tFileAttributes 0x%04hx", createParameters.FileAttributes);
            NpEtwTraceInfo(Create, "\tShareAccess 0x%08x", createParameters.ShareAccess);            
        }
	} __finally {
        NpEtwTraceFuncExit(Create, TRACE_LEVEL_RESERVED6);
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
    NpEtwTraceFuncEntry(ReadWrite, TRACE_LEVEL_RESERVED6);

	FLT_POSTOP_CALLBACK_STATUS postOperationStatus = FLT_POSTOP_FINISHED_PROCESSING;

	if (NT_SUCCESS(Data->IoStatus.Status)) {
		if (!FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, NpEtwPostReadWhenSafe, &postOperationStatus)) {
			NpEtwTraceError(ReadWrite, "Posting pipe read completion failed.");
		}
	} else {
		NpEtwTraceInfo(ReadWrite, "Pipe read Cbd 0x%p failed with status %!STATUS!", Data, Data->IoStatus.Status);
	}

    NpEtwTraceFuncExit(ReadWrite, TRACE_LEVEL_RESERVED6);

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

    NpEtwTraceFuncEntry(ReadWrite, TRACE_LEVEL_RESERVED6);

	__try {
		if (Data->IoStatus.Information == 0) {
			__leave;
		}

		NTSTATUS status = FltLockUserBuffer(Data);
		if (!NT_SUCCESS(status)) {
			NpEtwTraceError(ReadWrite, "Locking user buffer in post-read failed with status %!STATUS!", status);
			__leave;
		}

		__try {
			auto& readParams = Data->Iopb->Parameters.Read;

			PCHAR readBuffer = static_cast<PCHAR>(MmGetSystemAddressForMdlSafe(
                readParams.MdlAddress,
                LowPagePriority | MdlMappingNoWrite | MdlMappingNoExecute));
			if (!readBuffer) {
				__leave;
			}

            auto len = static_cast<short>(min(MAXSHORT, Data->IoStatus.Information));
            NpEtwTraceInfo(ReadWrite, "Pipe read data: %!HEXDUMP!", log_xstr(readBuffer, len));
		} __except (FsRtlIsNtstatusExpected(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            NpEtwTraceError(ReadWrite, "Accessing user buffer in post-read failed with status %!STATUS!", GetExceptionCode());
		}
	} __finally {

	}

    NpEtwTraceFuncExit(ReadWrite, TRACE_LEVEL_RESERVED6);
	
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
    NpEtwTraceFuncEntry(ReadWrite, TRACE_LEVEL_RESERVED6);

	FLT_POSTOP_CALLBACK_STATUS postOperationStatus = FLT_POSTOP_FINISHED_PROCESSING;

	if (NT_SUCCESS(Data->IoStatus.Status)) {
		if (!FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, NpEtwPostWriteWhenSafe, &postOperationStatus)) {
            NpEtwTraceError(ReadWrite, "Posting pipe write completion failed.");
		}
	} else {
        NpEtwTraceError(ReadWrite, "Pipe write failed with status %!STATUS!", Data->IoStatus.Status);
	}

    NpEtwTraceFuncExit(ReadWrite, TRACE_LEVEL_RESERVED6);

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

    NpEtwTraceFuncEntry(ReadWrite, TRACE_LEVEL_RESERVED6);

	__try {
		if (Data->IoStatus.Information == 0) {
			__leave;
		}

		NTSTATUS status = FltLockUserBuffer(Data);
		if (!NT_SUCCESS(status)) {
            NpEtwTraceError(ReadWrite, "Locking user buffer in post-write failed with status %!STATUS!", status);
			__leave;
		}

		__try {
			auto& writeParams = Data->Iopb->Parameters.Write;

			PCHAR writeBuffer = static_cast<PCHAR>(MmGetSystemAddressForMdlSafe(
                writeParams.MdlAddress,
                LowPagePriority | MdlMappingNoWrite | MdlMappingNoExecute));
			if (!writeBuffer) {
				__leave;
			}

            auto len = static_cast<short>(min(MAXSHORT, Data->IoStatus.Information));
            NpEtwTraceInfo(ReadWrite, "Pipe write data: %!HEXDUMP!", log_xstr(writeBuffer, len));
		} __except (FsRtlIsNtstatusExpected(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            NpEtwTraceError(ReadWrite, "Accessing user buffer in post-write failed with status %!STATUS!", GetExceptionCode());
		}
	} __finally {

	}

    NpEtwTraceFuncExit(ReadWrite, TRACE_LEVEL_RESERVED6);

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
