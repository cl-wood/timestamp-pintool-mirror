#ifndef __INSERT_CALLS_H
#define __INSERT_CALLS_H

// Clark Wood 2014

#include "pin.H"
#include <list>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <tuple>
#include "string.h"

namespace WINDOWS
{
	#include <Windows.h>
	#include <TlHelp32.h>	
}

using namespace std;

// Global externs
extern list<UINT64> counter_checks;
extern UINT num_GetTickCount;
extern vector<ADDRINT> loadLibraryReturnAddresses;
extern bool LoadLibraryReplaced;
extern UINT insCount;
extern UINT bblCount;
extern UINT threadCount;

// VirtualQuery global externs
extern WINDOWS::PMEMORY_BASIC_INFORMATION mbi_ptr;
extern int virtualQueryNum;
extern bool virtualQuery_replaced;

// Functions for InsertCalls
VOID CountBbl(UINT numInstInBbl);
VOID watch_clocks(UINT64 rdtsc_val);
VOID modGetTickCount(ADDRINT* ret);
VOID modWriteProcessMemory(ADDRINT* currentProc, ADDRINT* funcAddr, UINT* writePtr, UINT* sizeofPtr);
VOID modNTQueryObject(UINT* object_information);
VOID modGetProcAddress(char** procName);
VOID modBeforeGetProcAddress(char* procName);
VOID modEnumProcessModules(WINDOWS::HMODULE hMods[1024], WINDOWS::DWORD* cbNeeded);
VOID modFindWindow(char* procName);
VOID modProcessListWalkers(ADDRINT* retPtr, WINDOWS::DWORD pid);
// Should be "WINDOWS::LPCWSTR lpLibFileName", but that doesn't work
VOID beforeLoadLibraryW(char** lpLibFileName, ADDRINT returnIp);
VOID beforeLoadLibraryW(char** lpLibFileName, ADDRINT returnIp);
VOID WatchReturnIps(INS ins, VOID *);

// VirtualQuery
VOID modBeforeVirtualQuery(WINDOWS::MEMORY_BASIC_INFORMATION* lpBuffer, ADDRINT returnIp);
VOID modAfterVirtualQuery();
WINDOWS::SIZE_T replaceVirtualQuery(CONTEXT* pPinContext, AFUNPTR originalVirtualQuery, WINDOWS::LPCVOID lpAddress, WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer, WINDOWS::SIZE_T dwLength);
VOID firstInsVirtualQuery(UINT eax_val);
VOID lastInsVirtualQuery(ADDRINT mbi_local);


#endif
