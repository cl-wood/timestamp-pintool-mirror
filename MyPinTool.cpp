
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

/*
	Sample run in MyPinTools directory:
	\pin...\pin.exe -t MyPinTool.dll -- \Users\IEUser\Documents\Visual Studio 2010\Projects\hello\Debug\hello.exes
*/

#include "pin.H"

// Pintool Header Files
#include "modifyLoadLibrary.h"
#include "InsertCalls.h"

using namespace std;

extern ofstream OutFile;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "analysis.out", "specify output file name");

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool does stuff." << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
		for (INS ins = BBL_InsHead(bbl); ins != BBL_InsTail(bbl); ins = INS_Next(ins))
		{
			// TODO IF reads proc entry list for Pin's pid, change read value
			if (INS_IsRDTSC(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)watch_clocks, IARG_TSC, IARG_END);
			}
		}
	}
}


VOID Routine(RTN rtn, IMG img, VOID *)
{
	string routine_name = RTN_Name(rtn);
   	// Record all RTNs
	//OutFile << routine_name + "()" << endl;
	
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
	else if (routine_name.find("LoadLibrary") != string::npos
		     //&& routine_name.find("LoadLibraryA") == string::npos
		     //&& routine_name.find("LoadLibraryEx") == string::npos
		     && routine_name.find("LoadLibraryW") == string::npos)
	{
		//cout << routine_name << endl;
		//PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HMODULE), CALLINGSTD_DEFAULT, "LoadLibrary", 
		//							 PIN_PARG(WINDOWS::LPCTSTR), 
		//							 PIN_PARG_END());

		//RTN_ReplaceSignature(rtn, AFUNPTR(replaceLoadLibrary),
  //                       IARG_PROTOTYPE, proto,
  //                       IARG_CONTEXT,
  //                       IARG_ORIG_FUNCPTR,
  //                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
  //                       IARG_END);
		//PROTO_Free(proto);
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
			 //&& routine_name.find("VirtualQueryEx") == string::npos)
	{
		//PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::SIZE_T), CALLINGSTD_DEFAULT, "VirtualQueryEx", 
		//							 PIN_PARG(WINDOWS::HANDLE),
		//							 PIN_PARG(WINDOWS::LPCVOID), 
		//						     PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION),
		//							 PIN_PARG(WINDOWS::SIZE_T),
		//							 PIN_PARG_END());

		//RTN_ReplaceSignature(rtn, AFUNPTR(replaceVirtualQueryEx),
  //                       IARG_PROTOTYPE, proto,
  //                       IARG_CONTEXT,
  //                       IARG_ORIG_FUNCPTR,
  //                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		//				 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		//				 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		//				 IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
  //                       IARG_END);
		//PROTO_Free(proto);
	}

}



VOID checkRetAddr()
{

}

VOID WatchReturnIps(INS ins, VOID *)
{
	if (INS_Valid(ins) && INS_IsRet(ins))
	{

		// TODO working on instrumenting LoadLibrary since replace seems unreliable.
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)checkRetAddr, 
			           IARG_END);

		ADDRINT addr = INS_Address(ins);
		//OutFile << StringFromAddrint(addr) << endl;
		for (int i = 0; i < loadLibraryReturnAddresses.size(); i++)
		{
			if (addr == loadLibraryReturnAddresses[i])
			{
				OutFile << "MAYBE" << endl;
			}
		}
	}
}

				//PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::SIZE_T), CALLINGSTD_DEFAULT, "VirtualQuery", 
				//					 PIN_PARG(WINDOWS::LPCVOID), 
				//				     PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION),
				//					 PIN_PARG(WINDOWS::SIZE_T),
				//					 PIN_PARG_END());

				//RTN_ReplaceSignature(rtn, AFUNPTR(replaceVirtualQuery),
    //                     IARG_PROTOTYPE, proto,
    //                     IARG_CONTEXT,
    //                     IARG_ORIG_FUNCPTR,
    //                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//		 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//		 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
    //                     IARG_END);
				//PROTO_Free(proto);


// This routine is executed for each image.
VOID ImageLoad(IMG img, VOID *)
{
		cout << "Instrumenting " << IMG_Name(img) << endl;
		for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			RTN rtn = RTN_FindByName(img, "VirtualQuery");
			if (RTN_Valid(rtn))
			{
				// Instrument first and last instruction
				RTN_Open(rtn);

				WINDOWS::PMEMORY_BASIC_INFORMATION pass_mbi;

				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)modBeforeVirtualQuery, 
					   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					   IARG_PTR, &pass_mbi,
					   IARG_END);
				//INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR) firstInsVirtualQuery,
				//			   IARG_REG_VALUE, REG_EAX,
				//			   IARG_END);

				INS_InsertCall(RTN_InsTail(rtn), IPOINT_BEFORE, (AFUNPTR) lastInsVirtualQuery,
							   IARG_CALL_ORDER, CALL_ORDER_LAST,
							   IARG_PTR, &pass_mbi,
							   
							   IARG_END);


				RTN_Close(rtn);

				//string routine_name = RTN_Name(rtn);
					//RTN_Open(rtn);
					//RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)modBeforeVirtualQuery, 
					//   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					//   IARG_RETURN_IP,
					//   IARG_END);
					//RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modAfterVirtualQuery,
					//   IARG_END);
					//RTN_Close(rtn);
			}
		//for(RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		//	{
		//		//Routine(rtn, img, 0);
		//	}
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

		INS_AddInstrumentFunction(WatchReturnIps, 0);

		IMG_AddInstrumentFunction(ImageLoad, 0);
		IMG_AddUnloadFunction(ImageUnload, 0);

		// Called on exit
        PIN_AddFiniFunction(Fini, 0);
    }

	PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
