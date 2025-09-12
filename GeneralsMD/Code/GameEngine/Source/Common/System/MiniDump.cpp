#include "PreRTS.h"	// This must go first in EVERY cpp file int the GameEngine

#include "Common/MiniDump.h"
#include "Common/GameMemory.h"
#include "Common/FileSystem.h"
#include "Common/GameEngine.h"
#include "Common/ArchiveFileSystem.h"
#include "GameNetwork/LANAPI.h"
#include "GameNetwork/NetworkInterface.h"
#include "gitinfo.h"

struct _EXCEPTION_POINTERS* g_dumpException = NULL;
DWORD g_dumpExceptionThreadId = 0;

// The extern objects we want to explicitly include in an extended info minidump
extern LANAPI* TheLAN;

// forward declarations


LONG WINAPI MiniDumper::DumpingExceptionFilter(struct _EXCEPTION_POINTERS* e_info)
{
	g_dumpException = e_info;
	return EXCEPTION_EXECUTE_HANDLER;
}

void MiniDumper::TriggerMiniDump(Bool extendedInfo)
{
	if (!m_miniDumpInitialized)
	{
		// TODO: Log debug
		return;
	}

	__try
	{
		//*(int*)(NULL) = 1;
		__debugbreak();
	}
	__except (DumpingExceptionFilter(GetExceptionInformation()))
	{
		TriggerMiniDumpForException(g_dumpException, extendedInfo);
	}
}

// TODO: Incorporate into ReleaseCrash path as well as unhandled exception
void MiniDumper::TriggerMiniDumpForException(struct _EXCEPTION_POINTERS* e_info, Bool extendedInfo)
{
	if (!m_miniDumpInitialized)
	{
		return;
	}

	g_dumpException = e_info;
	g_dumpExceptionThreadId = GetCurrentThreadId();
	m_extendedInfoRequested = extendedInfo;

	// TODO: Should we not use this wait method since we are creating windows etc. ? See doc.
	DWORD wait = SignalObjectAndWait(m_dumpRequested, m_dumpComplete, INFINITE, FALSE);
	if (wait != WAIT_OBJECT_0)
	{
		// TODO: Something went wrong.. what can we do about it?
	} 
}

void MiniDumper::Initialize(const AsciiString& userDirPath)
{
	// Create & store dump folder
	strlcpy(m_dumpDir, userDirPath.str(), ARRAY_SIZE(m_dumpDir));
	strlcat(m_dumpDir, "CrashDumps\\", ARRAY_SIZE(m_dumpDir));
	if (!PathFileExists(m_dumpDir))
	{
		if (!CreateDirectory(m_dumpDir, NULL))
		{
			DEBUG_LOG(("Unable to create path for crash dumps at '%s': %u", m_dumpDir, GetLastError()));
			return;
		}
	}

	m_dumpRequested = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_dumpComplete = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_quitting = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (m_dumpRequested == NULL || m_dumpComplete == NULL || m_quitting == NULL)
	{
		// Something went wrong with the creation of the events..
		// TODO: Error logging
		return;
	}

	m_dumpThread = CreateThread(NULL, 0, MiniDumpThreadProc, this, CREATE_SUSPENDED, &m_dumpThreadId);
	if (!m_dumpThread)
	{
		// TODO: Clean up events
		// TODO: Error logging
		return;
	}

	if (!ResumeThread(m_dumpThread))
	{
		// TODO: Clean up events
		// TODO: Clean up thread
		// TODO: Error logging
		return;
	}

	m_miniDumpInitialized = true;

}

Bool MiniDumper::IsInitialized() const
{
	return m_miniDumpInitialized;
}

void MiniDumper::ShutDown()
{
	if (!m_miniDumpInitialized)
	{
		return;
	}

	DWORD waitRet = SignalObjectAndWait(m_quitting, m_dumpThread, 3000, false);
	if (waitRet != WAIT_OBJECT_0)
	{
		// TODO: Handle the trouble..
		return;
	}
	
	CloseHandle(m_dumpThread);
	m_dumpThread = NULL;
	CloseHandle(m_dumpComplete);
	m_dumpComplete = NULL;
	CloseHandle(m_dumpRequested);
	m_dumpRequested = NULL;
	CloseHandle(m_quitting);
	m_quitting = NULL;

	m_miniDumpInitialized = false;
}

DWORD MiniDumper::ThreadProcInternal()
{
	while (true)
	{
		HANDLE waitEvents[2] = { m_dumpRequested, m_quitting };
		DWORD event = WaitForMultipleObjects(2, waitEvents, FALSE, INFINITE);
		if (event == WAIT_OBJECT_0 + 0)
		{
			// m_dumpRequested
			CreateMiniDump(m_extendedInfoRequested);
			ResetEvent(m_dumpRequested);
			SetEvent(m_dumpComplete);
		}
		else if (event == WAIT_OBJECT_0 + 1)
		{
			// m_quitting
			return 0;
		}
		else
		{
			// Something went wrong.. BOO!
			return 1;
		}
	}
}

DWORD WINAPI MiniDumper::MiniDumpThreadProc(const LPVOID lpParam)
{
	if (lpParam == NULL)
	{
		// Expected parameters were not provided..
		return -1;
	}

	MiniDumper* dumper = static_cast<MiniDumper *>(lpParam);
	return dumper->ThreadProcInternal();
}


void MiniDumper::CreateMiniDump(Bool extendedInfo)
{
	HMODULE dbgHlp = GetModuleHandle("dbghelp.dll");
	if (dbgHlp == NULL)
	{
		// Load the dbghlp library from the system folder, as it contains the minidump functionality
		dbgHlp = LoadLibraryEx("dbghelp.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (dbgHlp == NULL)
		{
			DEBUG_LOG(("Unable to load system-provided dbghelp.dll, error code=%u", GetLastError()));
			return;
		}
	}

	// Create a unique dump file name, using the path from m_dumpDir, in m_dumpFile
	SYSTEMTIME sysTime;
	GetLocalTime(&sysTime);
	Char dumpTypeSpecifier = extendedInfo ? 'X' : 'M';
	DWORD currentProcessId = GetCurrentProcessId();
	DWORD currentThreadId = GetCurrentThreadId();

	//size_t copied = strlcpy(m_dumpFile, m_dumpDir, ARRAY_SIZE(m_dumpFile));
	//m_dumpDir is stored with trailing backslash in Initialize
	snprintf(m_dumpFile, ARRAY_SIZE(m_dumpFile), "%sCrash%c-%04d%02d%02d-%02d%02d%02d-%s-%ld-%ld.dmp",
		m_dumpDir, dumpTypeSpecifier, sysTime.wYear, sysTime.wMonth,
		sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
		GitShortSHA1, currentProcessId, currentThreadId);

	HANDLE dumpFile = CreateFile(m_dumpFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dumpFile == NULL || dumpFile == INVALID_HANDLE_VALUE)
	{
		DEBUG_LOG(("Unable to create dump file '%s', error=%u", m_dumpFile, GetLastError()));
		return;
	}

	PMINIDUMP_EXCEPTION_INFORMATION exceptionInfoPtr = NULL;
	if (g_dumpException != NULL)
	{
		MINIDUMP_EXCEPTION_INFORMATION exceptionInfo = {};
		exceptionInfo.ExceptionPointers = g_dumpException;
		exceptionInfo.ThreadId = g_dumpExceptionThreadId;
		exceptionInfo.ClientPointers = FALSE;
		exceptionInfoPtr = &exceptionInfo;
	}

	PMINIDUMP_CALLBACK_INFORMATION callbackInfoPtr = NULL;
	if (extendedInfo)
	{
		MINIDUMP_CALLBACK_INFORMATION callBackInfo = {};
		callBackInfo.CallbackRoutine = MiniDumpCallback;
		callBackInfo.CallbackParam = this;
		callbackInfoPtr = &callBackInfo;
	}
	//MINIDUMP_TYPE dumpType = MiniDumpNormal;
	//MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithDataSegs | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
	// Limit the available values as we have version 6.1 loaded, with only a subset of the desired flags available..
	MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithProcessThreadData | MiniDumpWithUnloadedModules);
	if (extendedInfo)
	{
		static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithProcessThreadData | MiniDumpWithUnloadedModules);
	}
	//MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithProcessThreadData | MiniDumpWithUnloadedModules);
	BOOL success = MiniDumpWriteDump(
		GetCurrentProcess(),
		currentProcessId,
		dumpFile, // File to write to
		dumpType,
		exceptionInfoPtr,
		NULL,
		callbackInfoPtr);

	if (!success)
	{
		DEBUG_LOG(("Unable to write minidump file, error=%u", GetLastError()));
	}
	else
	{
		DEBUG_LOG(("Successfully wrote minidump file to %s", m_dumpFile));
	}

	CloseHandle(dumpFile);
}

// TODO: Callback method
// - Filter dumping thread from dump
// - Add extra memory stuff, TheGlobalData, Memory Manager data etc.
BOOL CALLBACK MiniDumper::MiniDumpCallback(const PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput)
{
	if (CallbackParam == NULL || CallbackInput == NULL || CallbackOutput == NULL)
	{
		// TODO: Figure out what to do here
		DEBUG_LOG(("In MiniDumper::MiniDumpCallback, all was NULL!"));
		return false;
	}

	MiniDumper* dumper = static_cast<MiniDumper*>(CallbackParam);
	return dumper->CallbackInternal(*CallbackInput, *CallbackOutput);
}

// This is where the memory regions and things are being filtered
BOOL MiniDumper::CallbackInternal(const MINIDUMP_CALLBACK_INPUT& input, MINIDUMP_CALLBACK_OUTPUT& output)
{
	BOOL retVal = TRUE;
	DEBUG_LOG(("In MiniDumper::CallbackInternal, CallbackType is %u.", input.CallbackType));
	switch (input.CallbackType)
	{
	case MINIDUMP_CALLBACK_TYPE::IncludeModuleCallback:
		retVal = TRUE;
		break;
	case MINIDUMP_CALLBACK_TYPE::ModuleCallback:
	{
		char temp[MAX_PATH] = {};
		std::wcstombs(temp, input.Module.FullPath, MAX_PATH);
		DEBUG_LOG(("In MiniDumper::CallbackInternal, evaluating module %s", temp));
		// Only include data segments for the game and ntdll modules to keep dump size low
		if (output.ModuleWriteFlags & ModuleWriteDataSeg)
		{
			if (!wcsstr(input.Module.FullPath, L"generalszh.exe") && !wcsstr(input.Module.FullPath, L"generalsv.exe") && !wcsstr(input.Module.FullPath, L"ntdll.dll"))
			{
				// Exclude data segments for the module
				DEBUG_LOG(("In MiniDumper::CallbackInternal, excluding!", temp));
				output.ModuleWriteFlags &= (~ModuleWriteDataSeg);
			}
		}
		retVal = TRUE;
		break;
	}
	case MINIDUMP_CALLBACK_TYPE::IncludeThreadCallback:
		// We want all threads except the dumping thread
		retVal = TRUE;
		/*
		if (input.Thread.ThreadId == m_dumpThreadId)
		{
			retVal = FALSE;
		}
		else
		{
			retVal = TRUE;
		}
		*/
		break;
	case MINIDUMP_CALLBACK_TYPE::ThreadCallback:
		retVal = TRUE;
		break;
	case MINIDUMP_CALLBACK_TYPE::ThreadExCallback:
		retVal = TRUE;
		break;
	case MINIDUMP_CALLBACK_TYPE::MemoryCallback:
	{
		DEBUG_LOG(("In MiniDumper::CallbackInternal, about to go to DumpMemoryObjects."));
		retVal = DumpMemoryObjects(output.MemoryBase, output.MemorySize);
		break;
	}
	case MINIDUMP_CALLBACK_TYPE::CancelCallback:
		output.Cancel = FALSE;
		output.CheckCancel = FALSE;
		retVal = TRUE;
		break;
	}
	DEBUG_LOG(("In MiniDumper::CallbackInternal, retVal is %u.", retVal));
	return retVal;
}

BOOL MiniDumper::DumpMemoryObjects(ULONG64& memoryBase, ULONG& memorySize)
{
	BOOL moreToDo = TRUE;
	switch (m_dumpObjectsState)
	{
	case 0:
		if (TheWritableGlobalData != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheWritableGlobalData);
			memorySize = sizeof(GlobalData);
		}
		++m_dumpObjectsState;
		break;
	case 1:
		if (TheAudio != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheAudio);
			memorySize = sizeof(AudioManager);
		}
		++m_dumpObjectsState;
		break;
	case 2:
		if (TheMemoryPoolFactory != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheMemoryPoolFactory);
			memorySize = sizeof(MemoryPoolFactory);
		}
		++m_dumpObjectsState;
		break;
	case 3:
		if (TheDynamicMemoryAllocator != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheDynamicMemoryAllocator);
			memorySize = sizeof(DynamicMemoryAllocator);
		}
		++m_dumpObjectsState;
		break;
	case 4:
		if (TheNameKeyGenerator != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheNameKeyGenerator);
			memorySize = sizeof(NameKeyGenerator);
		}
		++m_dumpObjectsState;
		break;
	case 5:
		if (TheScienceStore != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheScienceStore);
			memorySize = sizeof(ScienceStore);
		}
		++m_dumpObjectsState;
		break;
	case 6:
		if (TheUpgradeCenter != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheUpgradeCenter);
			memorySize = sizeof(UpgradeCenter);
		}
		++m_dumpObjectsState;
		break;
	case 7:
		if (TheLAN != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheLAN);
			memorySize = sizeof(LANAPI);
		}
		++m_dumpObjectsState;
		break;
	case 8:
		if (TheArchiveFileSystem != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheArchiveFileSystem);
			memorySize = sizeof(ArchiveFileSystem);
		}
		++m_dumpObjectsState;
		break;
	case 9:
		if (TheFileSystem != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheFileSystem);
			memorySize = sizeof(FileSystem);
		}
		++m_dumpObjectsState;
		break;
	case 10:
		if (TheFirewallHelper != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheFirewallHelper);
			memorySize = sizeof(FirewallHelperClass);
		}
		++m_dumpObjectsState;
		break;
	case 11:
		if (TheChallengeGameInfo != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheChallengeGameInfo);
			memorySize = sizeof(SkirmishGameInfo);
		}
		++m_dumpObjectsState;
		break;
	case 12:
		if (TheGameInfo != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheGameInfo);
			memorySize = sizeof(GameInfo);
		}
		++m_dumpObjectsState;
		break;
	case 13:
		if (TheMessageStream != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheMessageStream);
			memorySize = sizeof(MessageStream);
		}
		++m_dumpObjectsState;
		break;
	case 14:
		if (TheCommandList != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheCommandList);
			memorySize = sizeof(CommandList);
		}
		++m_dumpObjectsState;
		break;
	case 15:
		if (TheNetwork != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheNetwork);
			memorySize = sizeof(NetworkInterface); // TODO: Should have been "Network" instead, figure out why it's not accessible
		}
		++m_dumpObjectsState;
		break;
	case 16:
		if (TheGameEngine!= NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheGameEngine);
			memorySize = sizeof(GameEngine);
		}
		++m_dumpObjectsState;
		break;
	case 17:
		/*
		if (TheIMEManager != NULL)
		{
			memoryBase = reinterpret_cast<ULONG64>(TheIMEManager);
			memorySize = sizeof(GameEngine);
		}
		*/
		++m_dumpObjectsState;
		m_dumpObjectsSubState = 0;
		break;
	case 18:
	{
		// Iterate through all the allocations of memory pools & blobs that has been done via the memory pool factory and include all of them
		if (TheMemoryPoolFactory == NULL)
		{
			++m_dumpObjectsState;
			break;
		}

		if (m_dumpObjectsSubState == 0)
		{
			// TODO: Is it bad to do this again? It was already done when the class was instantiated, but things could have changed since then?
			m_RangeIter = AllocationRangeIterator(TheMemoryPoolFactory);
			m_endRangeIter = AllocationRangeIterator(TheMemoryPoolFactory).end();
			++m_dumpObjectsSubState;
		}

		// m_RangeIter should != m_endRangeIter, unless the memory pool factory is corrupted (or has 0 entries)
		memoryBase = reinterpret_cast<ULONG64>(m_RangeIter->allocationAddr);
		memorySize = m_RangeIter->allocationSize;
		++m_dumpObjectsSubState;
		++m_RangeIter;

		if (m_RangeIter == m_endRangeIter)
		{
			++m_dumpObjectsState;
			m_dumpObjectsSubState = 0;
		}
		break;
	}
	case 19:
	{
		// Iterate through all the direct allocations ("raw blocks") done by DMAs, outside of the memory pool factory
		if (TheDynamicMemoryAllocator == NULL)
		{
			++m_dumpObjectsState;
			break;
		}

		DynamicMemoryAllocator* allocator = TheDynamicMemoryAllocator;
		for (int i = 0; i < m_dumpObjectsSubState; ++i)
		{
			allocator = allocator->getNextDmaInList();
		}

		MemoryPoolAllocatedRange rawBlockRange = {};
		int rawBlocksInDma = allocator->getRawBlockCount();
		if (m_dmaRawBlockIndex < rawBlocksInDma)
		{
			// Dump this block
			allocator->getAllocationRangeForRawBlockN(m_dmaRawBlockIndex, rawBlockRange);
			memoryBase = reinterpret_cast<ULONG64>(rawBlockRange.allocationAddr);
			memorySize = rawBlockRange.allocationSize;
			++m_dmaRawBlockIndex;
		}

		if (rawBlocksInDma == m_dmaRawBlockIndex)
		{
			// Advance to the next DMA
			++m_dumpObjectsSubState;
			m_dmaRawBlockIndex = 0;
			if (allocator->getNextDmaInList() == NULL)
			{
				// Done iterating through all the DMAs
				m_dumpObjectsSubState = 0;
				++m_dumpObjectsState;
			}
		}
		break;
	}
	default:
		// Done, set "no more stuff" values
		DEBUG_LOG(("In MiniDumper::CallbackInternal, reached the default case - all done!"));
		m_dumpObjectsState = 0;
		m_dumpObjectsSubState = 0;
		m_dmaRawBlockIndex = 0;
		memoryBase = 0;
		memorySize = 0;
		moreToDo = FALSE;
		break;
	}

	return moreToDo;
}
