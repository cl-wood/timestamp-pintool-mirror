
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

/*
	Sample run in MyPinTools directory:
	\pin...\pin.exe -t MyPinTool.dll -- \Users\IEUser\Documents\Visual Studio 2010\Projects\hello\Debug\hello.exes
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <list>
#include <vector>
#include <tuple>
#include "string.h"

namespace WINDOWS
{
	#include <Windows.h>
	#include <TlHelp32.h>	
}

using namespace std;

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT insCount = 0;        //number of dynamically executed instructions
UINT bblCount = 0;        //number of dynamically executed basic blocks
UINT threadCount = 0;     //total number of threads, including main thread
UINT num_GetTickCount = 0;

static int virtualQueryNum = 0;
bool virtualQuery_replaced = false;

WINDOWS::MEMORY_BASIC_INFORMATION mbi_struct;

ofstream OutFile;
list<UINT64> counter_checks;
vector<tuple<string, SYM> > functions;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "analysis.out", "specify output file name");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
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

VOID modLoadLibrary(char* arg0)
{
	//cout << "LoadLibrary " << arg0 << endl;
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

VOID modBeforeVirtualQuery(WINDOWS::MEMORY_BASIC_INFORMATION* lpBuffer)
{
	cout << "BEFORE" << endl;
	lpBuffer = &mbi_struct;

}

VOID modAfterVirtualQuery()
{
	cout << "AFTER" << endl;
}

static size_t replaceVirtualQuery(CONTEXT* context, AFUNPTR origVirtualQuery,
								  WINDOWS::LPCVOID lpAddress,
								  WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer,
								  WINDOWS::SIZE_T dwLength)
{
	size_t res = 0;
	mbi_struct.Protect = PAGE_EXECUTE_READ;
	cout << "HERE" << endl;

	PIN_CallApplicationFunction(context, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, origVirtualQuery,
								PIN_PARG(size_t), &res,
                                PIN_PARG(WINDOWS::LPCVOID), lpAddress,
                                PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION), lpBuffer,
								PIN_PARG(WINDOWS::SIZE_T), dwLength,
                                PIN_PARG_END());
	cout << "RES: " << res << endl;
	WINDOWS::PMEMORY_BASIC_INFORMATION mbi = lpBuffer;
	cout << "  mbi " << mbi->Protect << endl;
	cout << "  len " << dwLength << endl;

	//lpBuffer->Protect = mbi_struct.Protect;

	//ret = origVirtualQuery(lpAddress, lpBuffer, dwLength);
	return res;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
		
		for (INS ins = BBL_InsHead(bbl); ins != BBL_InsTail(bbl); ins = INS_Next(ins))
		{
			//OutFile << INS_Disassemble(ins) << endl;

			// IF reads proc entry list for Pin's pid, change read value


			if (INS_IsRDTSC(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)watch_clocks, IARG_TSC, IARG_END);
			}
		}
	
	}
}

/*
	For each routine called, check to see if the routine is of interest,
	and if so, insert analysis code.
 */
VOID Routine(RTN rtn, VOID *)
{
	string routine_name = RTN_Name(rtn);
   	// Record all RTNs
	OutFile << routine_name + "()" << endl;
	
	// For selected routines, record more info
	if (routine_name.find("GetTickCount") != string::npos)
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modGetTickCount, 
					   IARG_FUNCRET_EXITPOINT_REFERENCE,
					   IARG_END);
		RTN_Close(rtn);
	}
	else if (routine_name.find("FindWindow") != string::npos)
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modFindWindow, 
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
					   IARG_END);
		RTN_Close(rtn);
	}
	else if (routine_name.find("GetProcAddress") != string::npos)
	{

	}
	else if (routine_name.find("LoadLibrary") != string::npos)
	{
		RTN_Open(rtn);
		// Get func args before execution
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)modLoadLibrary, 
					   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  
					   IARG_END);
		RTN_Close(rtn);
	}
	else if (routine_name.find("WriteProcessMemory") != string::npos)
	{
		RTN_Open(rtn);

		// Make it write 0 bytes, a little hamfisted, should allow SOME writes in the future
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)modWriteProcessMemory, 
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3, // bytes to write
					   IARG_END);
		RTN_Close(rtn);
	}
	else if (routine_name.find("NTQueryObject") != string::npos)
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modNTQueryObject, 
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, // PVOID ObjectInformation
					   IARG_END);
		RTN_Close(rtn);
	}
	//!virtualQuery_replaced && 
	else if (routine_name.find("VirtualQuery") != string::npos)
	{
		cout << "VirtualQuery() #" << virtualQueryNum++ << endl;
		virtualQuery_replaced = true;

		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)modBeforeVirtualQuery, 
					   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
					   IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modAfterVirtualQuery, 
					   //IARG_FUNCRET_EXITPOINT_REFERENCE, 1,
					   IARG_END);
		RTN_Close(rtn);

		//PROTO proto = PROTO_Allocate(PIN_PARG(size_t), CALLINGSTD_DEFAULT, "VirtualQuery", 
		//								   PIN_PARG(WINDOWS::LPCVOID*), 
		//								   PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION*),
		//								   PIN_PARG(WINDOWS::SIZE_T*),
		//								   PIN_PARG_END());

		//RTN_ReplaceSignature(rtn, AFUNPTR(replaceVirtualQuery),
  //                       IARG_PROTOTYPE, proto,
  //                       IARG_CONTEXT,
  //                       IARG_ORIG_FUNCPTR,
  //                       IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
		//				 IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
		//				 IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
  //                       IARG_END);
	}

}

// This routine is executed for each image.
VOID ImageLoad(IMG img, VOID *)
{
	//if (IMG_IsMainExecutable(img)) 
	//{
		cout << "Instrumenting " << IMG_Name(img) << endl;
		for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			for(RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string routine_name = RTN_Name(rtn);
				Routine(rtn, 0);
			}
		}
	
}

VOID ImageUnload(IMG img, VOID *)
{

}

/*!
 * Print out analysis results.
 */
VOID Fini(INT32 code, VOID *v)
{
	OutFile.setf(ios::showbase);
    OutFile.close();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

	PIN_InitSymbols();
    string fileName = KnobOutputFile.Value();

    //if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    OutFile.open(KnobOutputFile.Value().c_str());

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        //PIN_AddThreadStartFunction(ThreadStart, 0);

		IMG_AddInstrumentFunction(ImageLoad, 0);
		IMG_AddUnloadFunction(ImageUnload, 0);

		// Called on exit
        PIN_AddFiniFunction(Fini, 0);
    }

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
