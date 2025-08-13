#include "PreRTS.h"	// This must go first in EVERY cpp file int the GameEngine

#include "Common/MiniDump.h"

void CreateMiniDump(struct _EXCEPTION_POINTERS* e_info)
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
	// TODO: Figure out user data directory
	// TODO: Create CrashDump folder in user data directory
	// TODO: Generate file name based on time, date, PID etc.
	HANDLE dumpFile = CreateFile("C:\\Users\\Paul\\Documents\\ZeroHour2.dmp", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dumpFile == NULL || dumpFile == INVALID_HANDLE_VALUE)
	{
		DEBUG_LOG(("Unable to open dump file, error=%u", GetLastError()));
		return;
	}

	MINIDUMP_EXCEPTION_INFORMATION exceptionInfo = {};
	exceptionInfo.ExceptionPointers = e_info;
	exceptionInfo.ThreadId = GetCurrentThreadId();
	exceptionInfo.ClientPointers = FALSE;

	//MINIDUMP_TYPE dumpType = MiniDumpNormal;
	//MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithDataSegs | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
	// Limit the available values as we have version 6.1 loaded, with only a subset of the desired flags available..
	MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithProcessThreadData | MiniDumpWithUnloadedModules);

	BOOL success = MiniDumpWriteDump(
		GetCurrentProcess(),
		GetCurrentProcessId(),
		dumpFile, // File to write to
		dumpType,
		&exceptionInfo,
		NULL,
		NULL);

	if (!success)
	{
		DEBUG_LOG(("Unable to write minidump file, error=%u", GetLastError()));
	}
	else
	{
		DEBUG_LOG(("Successfully wrote minidump file to %s", "C:\\Users\\Paul\\Documents\\ZeroHour2.dmp"));
	}

	CloseHandle(dumpFile);

}
