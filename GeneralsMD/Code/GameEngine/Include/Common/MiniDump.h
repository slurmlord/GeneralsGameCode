#pragma once

#include <imagehlp.h>

class MiniDumper
{
public:
	MiniDumper() {};
	void Initialize(const AsciiString& userDirPath);
	Bool IsInitialized() const;
	void TriggerMiniDump(Bool extendedInfo = false);
	void TriggerMiniDumpForException(struct _EXCEPTION_POINTERS* e_info, Bool extendedInfo = false);
	void ShutDown();
private:
	static DWORD WINAPI MiniDumpThreadProc(const LPVOID lpParam);
	static BOOL CALLBACK MiniDumpCallback(const PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
	static LONG WINAPI DumpingExceptionFilter(struct _EXCEPTION_POINTERS* e_info);
	DWORD ThreadProcInternal();
	BOOL CallbackInternal(const MINIDUMP_CALLBACK_INPUT& input, MINIDUMP_CALLBACK_OUTPUT& output);
	void CreateMiniDump(Bool extendedInfo);
	BOOL DumpMemoryObjects(ULONG64& memoryBase, ULONG& memorySize);

private:
	Bool m_miniDumpInitialized = false;
	Bool m_extendedInfoRequested = false;
	Char m_dumpDir[MAX_PATH] = {};
	Char m_dumpFile[MAX_PATH] = {};

	// Event handles
	HANDLE m_dumpRequested = NULL;
	HANDLE m_dumpComplete = NULL;
	HANDLE m_quitting = NULL;

	// Thread handles
	HANDLE m_dumpThread = NULL;
	DWORD m_dumpThreadId = 0;

	int m_dumpObjectsState = 0;
	int m_dumpObjectsSubState = 0;
	int m_dmaRawBlockIndex = 0;

	AllocationRangeIterator m_RangeIter; //AllocationRangeIterator(TheMemoryPoolFactory);
	AllocationRangeIterator m_endRangeIter; //AllocationRangeIterator(TheMemoryPoolFactory).end();
};
