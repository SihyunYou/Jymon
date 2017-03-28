/*
* @module   JyMon.c
* @brief    This is the main module of the JyMon miniFilter driver.
* @env      Kernel mode
*/

#ifndef __JYNUT_H__
#define __JYNUT_H__

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define NOTIFICATION_SIZE_TO_READ_FILE  1024
#define NOTIFICATION_SIZE_PATH 260
#define NOTIFICATION_SIZE_COMMAND_LINE 256
#define NOTIFICATION_SIZE_DETAIL 1024
#define NOTIFICATION_SIZE_VOLUME        4

#pragma pack(8)
typedef struct _JYMON_NOTIFICATION
{
	WCHAR ImagePath[NOTIFICATION_SIZE_PATH];
	WCHAR CommandLine[NOTIFICATION_SIZE_COMMAND_LINE];

	UCHAR EventClass;
	UCHAR Operation;
	WCHAR Path[NOTIFICATION_SIZE_PATH];
	CHAR Detail[NOTIFICATION_SIZE_DETAIL];
	ULONG Result;
	ULONGLONG Duration;

	ULONG ProcessId;
	ULONG ThreadId;
	ULONG SessionId;
	ULONG ParentProcessId;
} JYMON_NOTIFICATION, *PJYMON_NOTIFICATION;
#pragma pop

typedef struct _JYMON_REPLY
{
	ULONG Reserved;
} JYMON_REPLY, *PJYMON_REPLY;

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

#define ALLOW_GENERAL_DEBUG_PRINT       0x00000001
#define ALLOW_WARNING_DEBUG_PRINT       0x00000002
#define ALLOW_NOTIFIY_DEBUG_PRINT       0x00000003
#define ALLOW_ERROR_DEBUG_PRINT         0x00000004
#define ALLOW_DEBUG_PRINT               ALLOW_NOTIFIY_DEBUG_PRINT

const PWSTR JYMON_PORT_NAME = L"\\JyMonPort";

PKTIMER TimerObj;
PKDPC TimerDpcObj;

/*
* @brief    Structure that contains all the global data structures
*           used throughout this monitor.
*/
typedef struct _JYMON_DATA
{
	PDRIVER_OBJECT DriverObject; //  The object that identifies this driver.
	PFLT_FILTER FilterHandle; //  The filter handle that results from a call to FltRegisterFilter.
	PEPROCESS UserProcess; 	//  User process that connected to the port
	PFLT_PORT ServerPort; //  Listens for incoming connections
	PFLT_PORT ClientPort; 	//  Client port for a connection to user-mode
} JYMON_DATA, *PJYMON_DATA;

typedef struct _JYMON_STREAMHANDLE_CONTEXT
{
	BOOLEAN RescanRequired;
} JYMON_STREAMHANDLE_CONTEXT, *PJYMON_STREAMHANDLE_CONTEXT;

JYMON_DATA JyMonData;

/*************************************************************************
Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry
(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	);

NTSTATUS
JyMonUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
	);

NTSTATUS
JyMonInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
	);

NTSTATUS
JyMonInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS
JyMonPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
JyMonPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

NTSTATUS
JyMonPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
	);

VOID
JyMonPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
	);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, JyMonUnload)
#pragma alloc_text(PAGE, JyMonInstanceQueryTeardown)
#pragma alloc_text(PAGE, JyMonInstanceSetup)
#endif

//
// Operation registration
//

#define NOT_SUPPORTED_IRP FALSE

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_CREATE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_CLOSE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_READ,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_WRITE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_QUERY_INFORMATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_QUERY_EA,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_SET_EA,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_FLUSH_BUFFERS,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_DEVICE_CONTROL,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

#if NOT_SUPPORTED_IRP
	{ IRP_MJ_SHUTDOWN,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	NULL },             

	{ IRP_MJ_LOCK_CONTROL,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_CLEANUP,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_CREATE_MAILSLOT,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_QUERY_SECURITY,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_SET_SECURITY,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_QUERY_QUOTA,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_SET_QUOTA,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_PNP,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_MDL_READ,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_MDL_READ_COMPLETE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_VOLUME_MOUNT,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },

	{ IRP_MJ_VOLUME_DISMOUNT,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreOperation,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostOperation },
#endif

	{ IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] =
{
	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(JYMON_STREAMHANDLE_CONTEXT),
	'chBS' },

	{ FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,         //  Version
	0,                                //  Flags

	ContextRegistration,              //  Context
	Callbacks,                        //  Operation callbacks

	(PFLT_FILTER_UNLOAD_CALLBACK)JyMonUnload,                      //  MiniFilterUnload

	(PFLT_INSTANCE_SETUP_CALLBACK)JyMonInstanceSetup,               //  InstanceSetup
	(PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK)JyMonInstanceQueryTeardown,       //  InstanceQueryTeardown
	NULL,                             //  InstanceTeardownStart
	NULL,                             //  InstanceTeardownComplete

	NULL,                             //  GenerateFileName
	NULL,                             //  GenerateDestinationFileName
	NULL                              //  NormalizeNameComponent

};


EXTERN_C NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	unsigned char           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB{
	unsigned char                          Reserved1[2];
	unsigned char                          BeingDebugged;
	unsigned char                          Reserved2[1];
	PVOID                         Reserved3[2];
	PVOID                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	unsigned char                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID PostProcessInitRoutine;
	unsigned char                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

VOID TimerDpcRoutine(
	IN			PKDPC Dpc,
	IN OPTIONAL	PVOID DeferredContext,
	IN OPTIONAL	PVOID SystemArgument1,
	IN OPTIONAL	PVOID SystemArgument2
	)
{

}

PKTIMER
InitializeTimer(VOID)
{
	PKTIMER Timer;

	Timer = (PKTIMER)ExAllocatePool(NonPagedPool, sizeof(KTIMER));
	if (Timer == NULL)
	{
		return NULL;
	}

	KeInitializeTimer(Timer);
	return Timer;
}

PKDPC
SetTimer
(
	IN PKTIMER Timer,
	IN LONG Period,
	IN OPTIONAL KDEFERRED_ROUTINE TimerDpcRoutine,
	IN OPTIONAL PVOID DpcRoutineContext
	)
{
	LARGE_INTEGER TimePeriod;
	PKDPC DpcObj;

	DpcObj = NULL;

	if (TimerDpcRoutine != NULL)
	{
		DpcObj = (PKDPC)ExAllocatePool(NonPagedPool, sizeof(KDPC));
		if (DpcObj == NULL)
		{
			return NULL;
		}
		KeInitializeDpc(DpcObj, TimerDpcRoutine, DpcRoutineContext);
	}

	TimePeriod.QuadPart = -100;
	KeSetTimerEx(Timer, TimePeriod, Period, DpcObj);

	return DpcObj;
}

VOID
ReleaseTimer(IN PKTIMER Timer, IN OPTIONAL PKDPC DpcObj)
{
	KeCancelTimer(Timer);
	ExFreePool(Timer);

	if (DpcObj != NULL)
	{
		ExFreePool(DpcObj);
	}
}

/*
* @brief    This routine is called by the filter manager when a new instance is created.
*           We specified in the registry that we only want for manual attachments,
*           so that is all we should receive here.
*
* @param    FltObjects - Describes the instance and volume which we are being asked to setup.
* @param    Flags - Flags describing the type of attachment this is.
* @param    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
*           will attach.
* @param    VolumeFileSystemType - The file system formatted on this volume.
*
* @return   STATUS_SUCCESS            - we wish to attach to the volume
* @return   STATUS_FLT_DO_NOT_ATTACH  - no, thank you
*/
NTSTATUS
JyMonInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	FLT_ASSERT(FltObjects->Filter == JyMonData.FilterHandle);

	//
	//  Don't attach to network volumes.
	//
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}


/*
* @brief    This is called when an instance is being manually deleted by a
*           call to FltDetachVolume or FilterDetach thereby giving us a
*           chance to fail that detach request.
*
*           If this routine is not defined in the registration structure, explicit
*           detach requests via FltDetachVolume or FilterDetach will always be
*           failed.
*
* @param    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
*           opaque handles to this filter, instance and its associated volume.
* @param    Flags - Indicating where this detach request came from.
*
* @return   STATUS_SUCCESS - we allow instance detach to happen
*/
NTSTATUS
JyMonInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

#if ALLOW_DEBUG_PRINT <= ALLOW_GENERAL_DEBUG_EVENT
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonInstanceQueryTeardown: Entered\n");
#endif

	return STATUS_SUCCESS;
}


/*************************************************************************
MiniFilter initialization and unload routines.
*************************************************************************/

/*
* @brief    This is the initialization routine for this miniFilter driver. This
*           registers with FltMgr and initializes all global data structures.
*
* @param    Pointer to driver object created by the system to
*           represent this driver.
* @param    Unicode string identifying where the parameters for this
*           driver are located in the registry.
*
* @return   Routine can return non success error codes.
*/
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UnicodePortName;
	PSECURITY_DESCRIPTOR SecurityDescriptor;

	UNREFERENCED_PARAMETER(RegistryPath);

#if ALLOW_DEBUG_PRINT <= ALLOW_GENERAL_DEBUG_PRINT
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!DriverEntry: Entered\n");
#endif


	//
	//  Default to NonPagedPoolNx for non paged pool allocations where supported.
	//
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//
	//  Register with FltMgr to tell it our callback routines
	//
	Status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&JyMonData.FilterHandle);
	if (!NT_SUCCESS(Status))
	{
		switch (Status)
		{
		case STATUS_INSUFFICIENT_RESOURCES:
			//
			// FltRegisterFilter encountered a pool allocation failure. 
			// This is an error code.
			//
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_DEBUG_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry!FltRegisterFilter returned \
				STATUS_INSUFFICIENT_RESOURCES\n");
#endif
			break;

		case STATUS_INVALID_PARAMETER:
			//
			// One of the following :
			//
			// ? The Version member of the Registration structure was not set to 
			// FLT_REGISTRATION_VERSION.
			//
			// ? One of the non - NULL name - provider routines in the Registration 
			// structure was set to an invalid value.The GenerateFileNameCallback,
			// NormalizeNameComponentCallback, and NormalizeNameComponentExCallback 
			// members of FLT_REGISTRATION point to the name - provider routines.
			//
			// STATUS_INVALID_PARAMETER is an error code. 
			//
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_DEBUG_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry!FltRegisterFilter returned \
				STATUS_INVALID_PARAMETER\n");
#endif
			break;

		case STATUS_FLT_NOT_INITIALIZED:
			//  
			// The Filter Manager was not initialized when the filter tried to 
			// register. Make sure that the Filter Manager is loaded as a driver.
			// This is an error code.
			//
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_DEBUG_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry!FltRegisterFilter returned \
				STATUS_FLT_NOT_INITIALIZED\n");
#endif
			break;

		case STATUS_OBJECT_NAME_NOT_FOUND:
			//
			// The filter service key is not found in the registry. 
			// (registered service without your own inf file, in my case.)
			// 
			// The filter instance is not registered.
			//
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_DEBUG_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry!FltRegisterFilter returned \
				STATUS_OBJECT_NAME_NOT_FOUND\n");
#endif
			break;
		}
		return Status;
	}

	//
	//  Create a communication port.
	//
	RtlInitUnicodeString(&UnicodePortName, JYMON_PORT_NAME);

	//
	//  We secure the port so only ADMINs & SYSTEM can acecss it.
	//
	Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor,
		FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(Status))
	{
		InitializeObjectAttributes(&ObjectAttributes,
			&UnicodePortName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			SecurityDescriptor);
		Status = FltCreateCommunicationPort(JyMonData.FilterHandle,
			&JyMonData.ServerPort,
			&ObjectAttributes,
			NULL,
			(PFLT_CONNECT_NOTIFY)JyMonPortConnect,
			(PFLT_DISCONNECT_NOTIFY)JyMonPortDisconnect,
			NULL,
			1);
		//
		//  Free the security descriptor in all cases. It is not needed once
		//  the call to FltCreateCommunicationPort() is made.
		//
		FltFreeSecurityDescriptor(SecurityDescriptor);

		if (!NT_SUCCESS(Status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry: FltCreateCommunicationPort failed.\n");
			goto __CLEANUP_FILTERING__;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
			"JyMon!DriverEntry: FltCreateCommunicationPort succeeded.\n");
	}

	if (NT_SUCCESS(Status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
			"JyMon!DriverEntry: Trying to start filtering\n");
		Status = FltStartFiltering(JyMonData.FilterHandle);
		if (!NT_SUCCESS(Status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry: Unable to start filtering.\n");
			goto __CLEANUP_FILTERING__;
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!DriverEntry: Start filtering\n");
			return Status = STATUS_SUCCESS;
		}
	}

__CLEANUP_FILTERING__:
	FltCloseCommunicationPort(JyMonData.ServerPort);
	FltUnregisterFilter(JyMonData.FilterHandle);
	JyMonData.FilterHandle = NULL;

	return Status;
}


/*
* @brief    This is the unload routine for this miniFilter driver. This is called
*           when the minifilter is about to be unloaded. We can fail this unload
*           request if this is not a mandatory unload indicated by the Flags
*           parameter.
*
* @param    Indicating if this is a mandatory unload.
*
* @return   STATUS_SUCCESS.
*/
NTSTATUS
JyMonUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

#if ALLOW_DEBUG_PRINT <= ALLOW_GENERAL_DEBUG_PRINT
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonUnload: Entered\n");
#endif

	if (JyMonData.ServerPort)
	{
		FltCloseCommunicationPort(JyMonData.ServerPort);
	}
	if (JyMonData.FilterHandle)
	{
		FltUnregisterFilter(JyMonData.FilterHandle);
	}

	return STATUS_SUCCESS;
}

VOID
DpcRoutine(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
	)
{

}

/*************************************************************************
MiniFilter callback routines.
*************************************************************************/
/*
* @brief    This routine is a pre-operation dispatch routine for this miniFilter.
*           This is non-pageable because it could be called on the paging path.
*
* @param    Pointer to the filter callbackData that is passed to us.
* @param    Pointer to the FLT_RELATED_OBJECTS data structure containing
*           opaque handles to this filter, instance, its associated volume and
*           file object.
* @param    The context for the completion routine for this operation.
*
* @return   The status of the operation.
*/
FLT_PREOP_CALLBACK_STATUS
JyMonPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
	)
{
	NTSTATUS Status;
	PJYMON_STREAMHANDLE_CONTEXT JyMonContext = NULL;
	PJYMON_NOTIFICATION Notification = NULL;
	ULONG ReplyLength = sizeof(JYMON_REPLY);
	JYMON_REPLY Reply;
	LARGE_INTEGER Offset;
	HANDLE CurrentProcessId = PsGetCurrentProcessId();
	HANDLE CurrentThreadId = PsGetCurrentThreadId();

	UNREFERENCED_PARAMETER(CompletionContext);

	PKTIMER TimerObj = InitializeTimer();
	if (TimerObj == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	PKDPC TimerDpcObj = SetTimer(TimerObj, 1000, TimerDpcRoutine, NULL);
	if (!TimerDpcObj)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


#if ALLOW_DEBUG_PRINT <= ALLOW_GENERAL_DEBUG_PRINT
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonPreOperation : Entered\n");
#endif

	if (NULL == FltObjects->FileObject ||
		(HANDLE)4 == CurrentProcessId)
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	__try
	{
		Notification = (PJYMON_NOTIFICATION)FltAllocatePoolAlignedWithTag(FltObjects->Instance,
			NonPagedPool,
			sizeof(JYMON_NOTIFICATION),
			'nacS');
		if (NULL == Notification)
		{
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_DEBUG_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!JyMonPreOperation : Couldn't allocate memory, line %i\n",
				__LINE__);
#endif
			__leave;
		}
		RtlZeroMemory(Notification, sizeof(JYMON_NOTIFICATION));
		
		//
		//  The buffer can be a raw user buffer. Protect access to it
		//
		__try
		{
			PPROCESS_BASIC_INFORMATION Pbi = NULL;
			PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
			PPEB Peb = NULL;
			Pbi = (PPROCESS_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool,
				sizeof(PROCESS_BASIC_INFORMATION),
				NULL);
			if (!Pbi)
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			Status = ZwQueryInformationProcess(ZwCurrentProcess(),
				ProcessBasicInformation,
				Pbi,
				sizeof(PROCESS_BASIC_INFORMATION),
				NULL);
			if (!NT_SUCCESS(Status) ||
				!Pbi->PebBaseAddress)
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			
			Peb = Pbi->PebBaseAddress;
			ProcessParameters = Peb->ProcessParameters;

			RtlCopyMemory(Notification->ImagePath,
				ProcessParameters->ImagePathName.Buffer,
				ProcessParameters->ImagePathName.Length);
			RtlCopyMemory(Notification->CommandLine,
				ProcessParameters->CommandLine.Buffer,
				ProcessParameters->CommandLine.Length);
			Notification->Operation = Data->Iopb->MajorFunction;

			RtlCopyMemory(Notification->Path,
				FltObjects->FileObject->FileName.Buffer,
				min(FltObjects->FileObject->FileName.Length, NOTIFICATION_SIZE_PATH - 1));

			Notification->Result = Data->IoStatus.Status;

			Notification->SessionId = Peb->SessionId;
			Notification->ProcessId = (ULONG)CurrentProcessId;
			Notification->ThreadId = (ULONG)CurrentThreadId;
			Notification->ParentProcessId = Pbi->InheritedFromUniqueProcessId;

		
			Notification->Duration = TimerObj->DueTime.QuadPart;
			if (NT_SUCCESS(Status))
			{
				DbgPrint("Image Path : %S\n"
					"Command Line : %S\n"
					"Operation : %d\n"
					"Path : %S\n"
					"Result : %x\n"
					"Duration : %lld\n"
					"Process ID : %d\n"
					"Thread ID : %d\n"
					"Session ID : %d\n"
					"Parent Process ID : %d\n",
					Notification->ImagePath,
					Notification->CommandLine,
					Notification->Operation,
					Notification->Path,
					Notification->Result,
					Notification->Duration,
					Notification->ProcessId,
					Notification->ThreadId,
					Notification->SessionId,
					Notification->ParentProcessId);
			}
			
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			//
			//  Error accessing buffer. Complete i/o with failure
			//
			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
			__leave;
		}

		Offset.QuadPart = 0;
		Status = FltSendMessage(JyMonData.FilterHandle,
			&JyMonData.ClientPort,
			Notification,
			sizeof(JYMON_NOTIFICATION),
			NULL, // Without reply
			&ReplyLength,
			NULL);

		//
		// Reserved codes for reply messages to filter.
		//
		/*
		if (STATUS_SUCCESS == Status)
		{
			Reply.Reserved = ((PJYMON_REPLY)&Notification)->Reserved;
		}
		else
		{
#if ALLOW_DEBUG_PRINT <= ALLOW_ERROR_NOTIFY_PRINT
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!JyMonPostOperation : Couldn't send message to user-mode, status 0x%X\n",
				Status);
#endif
		}
		*/


	}
	__finally
	{
		if (NULL != Notification)
		{
			ExFreePoolWithTag(Notification, 'nacS');
		}

		ReleaseTimer(TimerObj, TimerDpcObj);
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/*
* @brief    Post create callback.
*
* @param    Data - The structure which describes the operation parameters.
* @param    FltObject - The structure which describes the objects affected by this
*           operation.
* @param    CompletionContext - The operation context passed fron the pre-create
*           callback.
* @param    Flags - Flags to say why we are getting this post-operation callback.
*
* @return   FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
*           access to this file, hence undo the open
*/
FLT_POSTOP_CALLBACK_STATUS
JyMonPostOperation(
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

#if ALLOW_DEBUG_PRINT <= ALLOW_GENERAL_DEBUG_PRINT
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonPostOperation : Entered\n");
#endif

	return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
* @brief    This is called when user-mode connects to the server port - to establish a
*           connection.
* @param    This is the client connection port that will be used to send messages from
*           the filter
* @param    The context associated with this port when the minifilter created this port.
* @param    Context from entity connecting to this port (most likely your user mode service)
* @param    Size of ConnectionContext in bytes
* @param    Context to be passed to the port disconnect routine.
* @return   STATUS_SUCCESS - to accept the connection
*/
NTSTATUS
JyMonPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(JyMonData.ClientPort == NULL);
	FLT_ASSERT(JyMonData.UserProcess == NULL);

	//
	//  Set the user process and port. In a production filter it may
	//  be necessary to synchronize access to such fields with port
	//  lifetime. For instance, while filter manager will synchronize
	//  FltCloseClientPort with FltSendMessage's reading of the port 
	//  handle, synchronizing access to the UserProcess would be up to
	//  the filter.
	//
	JyMonData.UserProcess = PsGetCurrentProcess();
	JyMonData.ClientPort = ClientPort;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonPortConnect : Connected, Port=0x%P\n", ClientPort);

	return STATUS_SUCCESS;
}

/*
* @brief    This is called when the connection is torn-down. We use it to close our
*           handle to the connection
* @param    Context from the port connect routine.
*/
VOID
JyMonPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
	)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonPortDisconnect : Disconnected, Port=0x%P\n", JyMonData.ClientPort);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//
	FltCloseClientPort(JyMonData.FilterHandle, &JyMonData.ClientPort);

	//
	//  Reset the user-process field.
	//
	JyMonData.UserProcess = NULL;
}



#endif /* __JYNUT_H__ */