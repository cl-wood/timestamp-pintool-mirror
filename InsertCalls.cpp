// Clark Wood 2014
#include "InsertCalls.h"

// Globals
ofstream OutFile;
list<UINT64> counter_checks;
UINT num_GetTickCount = 0;
vector<ADDRINT> loadLibraryReturnAddresses;

static bool LoadLibraryReplaced = false;
UINT insCount = 0;
UINT bblCount = 0;
UINT threadCount = 0;

// VirtualQuery global declarations/assignments
static WINDOWS::PMEMORY_BASIC_INFORMATION mbi_ptr;
static int virtualQueryNum = 0;
bool virtualQuery_replaced = false;

VOID CountBbl(UINT numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

VOID printIns(string insDis)
{
	OutFile << insDis << endl;
}

VOID watch_clocks(UINT64 rdtsc_val)
{
	counter_checks.push_back(rdtsc_val);
	//cout << "rdtsc reads:\t" << rdtsc_val << endl;
}

/*
	Always change the return value of GetTickCount() to 0.
 */
VOID modGetTickCount(ADDRINT* ret)
{
	num_GetTickCount++;
	//OutFile << "GetTickCount() #" << num_GetTickCount << endl;
	*ret = 0;
}

// ex. from eXait if(WriteProcessMemory(GetCurrentProcess(), (LPVOID)FuncAddr, &toWrite, sizeof(toWrite), &BytesWritten))
VOID modWriteProcessMemory(ADDRINT* currentProc, ADDRINT* funcAddr, UINT* writePtr, UINT* sizeofPtr)
{
	//cout << "WriteProcessMemory " << *currentProc << "\t" 
	//							  << *funcAddr << "\t"
	//							  << *writePtr << "\t"
	//							  << *sizeofPtr << endl;

	// Write 0 bytes
	*sizeofPtr = 0;
}

// counter-eXait detect by event handles
// TODO less heavy-handed approach, check to see if objectName.Buffer has "PIN_IPC"
VOID modNTQueryObject(UINT* object_information)
{
	*object_information = NULL;
}


// TODO doesn't work, possibly b/c GetProcAddress() returns from another function it calls
// Anything involving procName screws everything up, doesn't even load eXait
VOID modGetProcAddress(char** procName)
{
	//char* tempStr;
	//strcpy(tempStr, *procName);
	////printf("GetProcAddress:\t%s\n", *procName);
	//string s = tempStr;
	//char * functions[] = {"Pin", "Charm", 
	//				     //"KiUserApcDispatcher", "KiUserCallbackDispatcher", "KiUserExceptionDispatcher", "LdrInitializeThunk",
	//						"ClientInt" };
	//int numberOfFunctions = sizeof(functions) / sizeof(functions[0]);

	//for (int i = 0; i < numberOfFunctions; i++) 
	//{
	//	if (s.find(functions[i]) != string::npos)
	//	{
	//		cout << s<< endl;
	//	}
	//}
}

VOID modBeforeGetProcAddress(char* procName)
{
	string s = procName;
	if (s.find("Pin") != string::npos || s.find("Charm") != string::npos)
	{
		cout << s << endl;
		//procName = "blahblahblah";
	}
}

VOID modEnumProcessModules(WINDOWS::HMODULE hMods[1024], WINDOWS::DWORD* cbNeeded)
{
	//for(unsigned int i = 0; i < (*cbNeeded / sizeof(WINDOWS::HMODULE)); i++)
 //   {
	//	if(GetProcAddress(hMods[i], "CharmVersionC"))
	//	{
	//		cout << "HERE" << endl;
	//	}
	//}
}
//
//WINDOWS::FARPROC replacementGetProcAddress(const CONTEXT *context, THREADID tid, AFUNPTR origWatchRtn,
//	                                     WINDOWS::HMODULE hModule, WINDOWS::LPCSTR lpProcName)
//	                                     //int hModule, char* lpProcName)
//{
//	WINDOWS::FARPROC res;
//	cout << "GetProcAddress: " << lpProcName << endl;
//	PIN_CallApplicationFunction(context, tid, CALLINGSTD_DEFAULT, origWatchRtn,
//                                PIN_PARG(WINDOWS::FARPROC), res,
//								PIN_PARG(WINDOWS::HMODULE), hModule, 
//								PIN_PARG(WINDOWS::LPCSTR), lpProcName, 
//								PIN_PARG_END());
//
//
//	//res = WINDOWS::GetProcAddress((WINDOWS::HMODULE)hModule, lpProcName);
//
//	return res;
//}

VOID modFindWindow(char* procName)
{
	// Change to NULL, which is unlikely to be the name of an open window?
}

VOID modProcessListWalkers(ADDRINT* retPtr, WINDOWS::DWORD pid)
{
	cout << *retPtr << "\t" << endl;

	*retPtr = false;

	//cout << processEntry->szExeFile << "\t" << pid << endl;
	//if (processEntry->th32ProcessID == pid)
	//{
	//	cout << "FOUND " << pid << endl;
	//	//processEntry->th32ProcessID =
	//}
}

VOID modBeforeVirtualQuery(WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer, ADDRINT pass_mbi)
{
	//OutFile << StringFromAddrint(returnIp) << endl;
	pass_mbi = 3;
	WINDOWS::MEMORY_BASIC_INFORMATION m = *lpBuffer;
	PIN_SafeCopy((VOID*)mbi_ptr, (VOID*) lpBuffer, sizeof(WINDOWS::PMEMORY_BASIC_INFORMATION));

	OutFile << __FUNCTION__ << "\t" 
		    //<< StringFromAddrint(returnIp) << "\t" 
			<< &((WINDOWS::MEMORY_BASIC_INFORMATION) *lpBuffer) << "\t" << &m 
			<< "\t" << mbi_ptr->Protect << endl;

	// maybe PIN_SafeCopy?
	//return_ptr = returnIp;
	//PIN_SafeCopy((VOID*)return_ptr, (VOID*)returnIp, sizeof(ADDRINT));
	//return_ptr = returnIp;
	//cout << return_ptr << endl;

}

VOID modAfterVirtualQuery()
{
	OutFile << "AFTER: " << endl;// << StringFromAddrint(returnIp) << endl;

	//mbi_ptr->Protect = PAGE_EXECUTE_READ;
	//WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer = (WINDOWS::PMEMORY_BASIC_INFORMATION) ret;
	//cout << mbi_ptr << endl;

}

UINT insF = 0;
UINT insL = 0;
VOID firstInsVirtualQuery(UINT eax_val)
{
	OutFile << ++insF << "\t BEF" << eax_val << endl;
}
VOID lastInsVirtualQuery(ADDRINT mbi_local)
{
	//WINDOWS::PMEMORY_BASIC_INFORMATION my_mbi = (WINDOWS::PMEMORY_BASIC_INFORMATION)mbi_local;

	OutFile << ++insL << "\t AFT\t" << mbi_local
		    << endl;//<< (mbi_ptr->Protect == PAGE_EXECUTE_READWRITE) << endl;
}


WINDOWS::SIZE_T replaceVirtualQuery(CONTEXT* pPinContext,
									AFUNPTR originalVirtualQuery,		    
								    WINDOWS::LPCVOID lpAddress,
									WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer,
									WINDOWS::SIZE_T dwLength)
{
	WINDOWS::SIZE_T res;
	PIN_CallApplicationFunction(pPinContext, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, originalVirtualQuery,
								PIN_PARG(WINDOWS::SIZE_T), &res,
                                PIN_PARG(WINDOWS::LPCVOID), lpAddress,
                                PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION), lpBuffer,
								PIN_PARG(WINDOWS::SIZE_T), dwLength,
                                PIN_PARG_END());
	return res;
}


//WINDOWS::HMODULE replaceLoadLibrary(CONTEXT* pPinContext,
//									AFUNPTR originalVirtualQuery,
//								    WINDOWS::LPCTSTR lpFileName)
//{
//	cout << "LoadLibrary: " << lpFileName << endl;
//
//	WINDOWS::HMODULE res;
//	PIN_CallApplicationFunction(pPinContext, PIN_ThreadId(),
//                                CALLINGSTD_DEFAULT, originalVirtualQuery,
//								PIN_PARG(WINDOWS::LPCTSTR), lpFileName,
//                                PIN_PARG_END());
//
//	return res;
//}

VOID beforeLoadLibraryW(char** lpLibFileName, ADDRINT returnIp)
{
	//OutFile << "LoadLibraryW: " << *lpLibFileName << endl;
	//OutFile << "Called at: " << StringFromAddrint(returnIp) << endl;
	loadLibraryReturnAddresses.push_back(returnIp);
}





				//cout << RTN_Name(rtn) << endl;
				//RTN_Open(rtn);
				//RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)beforeLoadLibraryW, 
				//			   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
				//	           IARG_RETURN_IP,
				//	           IARG_END);
				//RTN_Close(rtn);
				// This never seems to work, probably b/c crazy under the hood windows stuff.
				//PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HMODULE), CALLINGSTD_DEFAULT, "LoadLibraryW", 
				//					 PIN_PARG(WINDOWS::LPCTSTR), 
				//					 PIN_PARG_END());

				//RTN_ReplaceSignature(rtn, AFUNPTR(replaceLoadLibrary),
    //                     IARG_PROTOTYPE, proto,
    //                     IARG_CONTEXT,
    //                     IARG_ORIG_FUNCPTR,
    //                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
    //                     IARG_END);
				//PROTO_Free(proto);