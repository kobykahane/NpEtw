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
        status = EventRegisterNpEtw();
        if (!NT_SUCCESS(status)) {
            NpEtwTraceError(General, "EventRegisterNpEtw failed with status %!STATUS!", status);
            __leave;
        }

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

            NTSTATUS etwStatus = EventUnregisterNpEtw();
            if (!NT_SUCCESS(etwStatus)) {
                NpEtwTraceError(General, "EventUnregisterNpEtw failed with status %!STATUS!", status);
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

    NTSTATUS status = EventUnregisterNpEtw();
    if (!NT_SUCCESS(status)) {
        NpEtwTraceError(General, "EventUnregisterNpEtw failed with status %!STATUS!", status);
    }

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

    PAGED_CODE();

    NpEtwTraceFuncEntry(Create, TRACE_LEVEL_RESERVED6);

    FLT_PREOP_CALLBACK_STATUS cbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    *CompletionContext = nullptr;

    PFLT_FILE_NAME_INFORMATION fileNameInfo = nullptr;
    __try {
        // We pick up the name in pre-create for two reasons:
        // - If the create fails, the name cannot be queried in post-create.
        // - If the create succeeds, this is the cheapest place to pick it up since FileObject->FileName is valid.		
        NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
        if (!NT_SUCCESS(status)) {
            NpEtwTraceError(Create, "Retreiving pipe name in pre-create/createnp failed with status %!STATUS!", status);
            __leave;
        }

        *CompletionContext = fileNameInfo;

        cbStatus = FLT_PREOP_SYNCHRONIZE;
    } __finally {
        NpEtwTraceFuncExit(Create, TRACE_LEVEL_RESERVED6);
    }

    return cbStatus;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI NpEtwPostCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    NpEtwTraceFuncEntry(Create, TRACE_LEVEL_RESERVED6);
    
    auto fileNameInfo = static_cast<PFLT_FILE_NAME_INFORMATION>(CompletionContext);
    __try {
        if (!fileNameInfo) {
            NpEtwTraceError(Create, "Post create/createnp invoked without file name in completion context.");
            __leave;
        }

        WCHAR fileNameBuffer[64];
        PWCHAR fileName = nullptr;
        if ((fileNameInfo->Name.MaximumLength <= fileNameInfo->Name.Length) ||
                (fileNameInfo->Name.Buffer[fileNameInfo->Name.Length / 2] != L'\0')) {
            // Ugh.
            NTSTATUS status = RtlStringCchCopyUnicodeString(fileNameBuffer, ARRAYSIZE(fileNameBuffer), &fileNameInfo->Name);
            if (NT_ERROR(status)) {
                NpEtwTraceError(Create, "Copying file name to buffer failed with status %!STATUS!", status); 
                __leave;
            }
            fileName = fileNameBuffer;

            NpEtwTraceWarning(Create, "Got file name without null terminator in post-create/createnp.");
        } else {
            fileName = fileNameInfo->Name.Buffer;
        }

        ULONG issuingThreadId = HandleToUlong(PsGetThreadId(Data->Thread));
        auto& ioStatus = Data->IoStatus.Status;
        auto& fileObject = FltObjects->FileObject;
        auto& fileKey = FltObjects->FileObject->FsContext;

        NpEtwTraceInfo(Create, "%s Cbd 0x%p FileObject 0x%p FileKey 0x%p IoStatus %!STATUS!",
            FltGetIrpName(Data->Iopb->MajorFunction), Data, fileObject, fileKey, ioStatus);
        NpEtwTraceInfo(Create, "\tIssuingThreadId 0x%08lx", issuingThreadId);

        switch (Data->Iopb->MajorFunction) {
        case IRP_MJ_CREATE:
            {
                auto& createParameters = Data->Iopb->Parameters.Create;
                auto& createOptions = createParameters.Options;
                auto& shareAccess = createParameters.ShareAccess;
                auto& createAttributes = createParameters.FileAttributes;

                NpEtwTraceInfo(Create, "\tCreateOptions 0x%08x", createOptions);
                NpEtwTraceInfo(Create, "\tShareAccess 0x%04hx", shareAccess);
                NpEtwTraceInfo(Create, "\tFileAttributes 0x%04hx", createAttributes);

                EventWriteCreateEvent(
                    nullptr, Data, fileObject, fileKey, issuingThreadId, ioStatus, createOptions, createAttributes, shareAccess, fileName);
            }         
            break;
        case IRP_MJ_CREATE_NAMED_PIPE:
            {
                auto& createPipeParameters = Data->Iopb->Parameters.CreatePipe;
                auto& createOptions = createPipeParameters.Options;
                auto& shareAccess = createPipeParameters.ShareAccess;
                auto namedPipeCreateParameters = static_cast<PNAMED_PIPE_CREATE_PARAMETERS>(createPipeParameters.Parameters);
                auto& namedPipeType = namedPipeCreateParameters->NamedPipeType;
                auto& readMode = namedPipeCreateParameters->ReadMode;
                auto& completionMode = namedPipeCreateParameters->CompletionMode;
                auto& maxInstances = namedPipeCreateParameters->MaximumInstances;
                auto& inboundQuota = namedPipeCreateParameters->InboundQuota;
                auto& outboundQuota = namedPipeCreateParameters->OutboundQuota;
                auto& defaultTimeout = namedPipeCreateParameters->DefaultTimeout.QuadPart;
                auto& timeoutSpecified = namedPipeCreateParameters->TimeoutSpecified;

                NpEtwTraceInfo(Create, "\tCreateOptions 0x%08x", createOptions);
                NpEtwTraceInfo(Create, "\tShareAccess 0x%04hx", shareAccess);
                NpEtwTraceInfo(Create, "\tNamedPipeType 0x%08lx", namedPipeType);
                NpEtwTraceInfo(Create, "\tReadMode 0x%08lx", readMode);
                NpEtwTraceInfo(Create, "\tCompletionMode 0x%08lx", completionMode);
                NpEtwTraceInfo(Create, "\tMaximumInstances 0x%08lx", maxInstances);
                NpEtwTraceInfo(Create, "\tInboundQuota 0x%08lx", inboundQuota);
                NpEtwTraceInfo(Create, "\tOutboundQuota 0x%08lx\n", outboundQuota);
                if (namedPipeCreateParameters->TimeoutSpecified) {
                    NpEtwTraceInfo(Create, "\tDefaultTimeout 0x%llx", defaultTimeout);
                }
                NpEtwTraceInfo(Create, "\tTimeoutSpecified %!BOOLEAN!", timeoutSpecified);

                EventWriteCreateNamedPipeEvent(
                    nullptr, Data, fileObject, fileKey, issuingThreadId, ioStatus, createOptions, shareAccess, fileName, namedPipeType, readMode,
                    completionMode, maxInstances, inboundQuota, outboundQuota, timeoutSpecified, defaultTimeout);
            }
            break;
        }
    } __finally {
        if (fileNameInfo) {
            FltReleaseFileNameInformation(fileNameInfo);
        }
    }

    NpEtwTraceFuncExit(Create, TRACE_LEVEL_RESERVED6);

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

            PUCHAR readBuffer = static_cast<PUCHAR>(MmGetSystemAddressForMdlSafe(
                readParams.MdlAddress,
                LowPagePriority | MdlMappingNoWrite | MdlMappingNoExecute));
            if (!readBuffer) {
                __leave;
            }

            auto len = static_cast<short>(min(MAXSHORT, Data->IoStatus.Information));           
            NpEtwTraceInfo(ReadWrite, "IRP_MJ_READ Cbd 0x%p FileObject 0x%p Information 0x%Ix Data: %!HEXDUMP!",
                Data, FltObjects->FileObject, Data->IoStatus.Information, log_xstr(readBuffer, len));
            EventWriteReadEvent(
                nullptr, Data, FltObjects->FileObject, FltObjects->FileObject->FsContext, HandleToUlong(PsGetThreadId(Data->Thread)),
                static_cast<ULONG>(Data->IoStatus.Information), Data->Flags, readBuffer);
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

            PUCHAR writeBuffer = static_cast<PUCHAR>(MmGetSystemAddressForMdlSafe(
                writeParams.MdlAddress,
                LowPagePriority | MdlMappingNoWrite | MdlMappingNoExecute));
            if (!writeBuffer) {
                __leave;
            }

            auto len = static_cast<short>(min(MAXSHORT, Data->IoStatus.Information));            
            NpEtwTraceInfo(ReadWrite, "IRP_MJ_WRITE Cbd 0x%p FileObject 0x%p Information 0x%Ix Data: %!HEXDUMP!",
                Data, FltObjects->FileObject, Data->IoStatus.Information, log_xstr(writeBuffer, len));
            EventWriteWriteEvent(
                nullptr, Data, FltObjects->FileObject, FltObjects->FileObject->FsContext, HandleToUlong(PsGetThreadId(Data->Thread)),
                static_cast<ULONG>(Data->IoStatus.Information), Data->Flags, writeBuffer);
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
