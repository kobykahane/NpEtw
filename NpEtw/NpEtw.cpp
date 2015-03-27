#include "NpEtw.h"

extern "C" {

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, NpEtwUnload)
#pragma alloc_text(PAGE, NpEtwInstanceQueryTeardown)
#pragma alloc_text(PAGE, NpEtwInstanceSetup)
#endif

PFLT_FILTER gFilterHandle = nullptr;

CONST FLT_OPERATION_REGISTRATION OperationCallbacks[] = {
    { IRP_MJ_CREATE,              0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_CREATE_NAMED_PIPE,   0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_CLOSE,               0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_READ,                0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_WRITE,               0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_QUERY_INFORMATION,   0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_SET_INFORMATION,     0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_FLUSH_BUFFERS,       0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_DIRECTORY_CONTROL,   0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_CLEANUP,             0, NpEtwPreOperation, NpEtwPostOperation },
//  { IRP_MJ_CREATE_MAILSLOT,     0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_QUERY_SECURITY,      0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_SET_SECURITY,        0, NpEtwPreOperation, NpEtwPostOperation },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
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
