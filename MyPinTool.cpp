
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

using namespace std;

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT insCount = 0;        //number of dynamically executed instructions
UINT bblCount = 0;        //number of dynamically executed basic blocks
UINT threadCount = 0;     //total number of threads, including main thread

ofstream OutFile;
list<UINT64> counter_checks;
vector<tuple<string, SYM> > functions;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "instructions.out", "specify output file name");

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
	cout << "rdtsc reads:\t" << rdtsc_val << endl;
}


/*
	Always change the return value of GetTickCount to 0.
 */
VOID modGetTickCount(ADDRINT* ret)
{
	cout << "GetTickCount() = " << *ret << endl;
	*ret = 0;
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
			OutFile << INS_Disassemble(ins) << endl;

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
	if (routine_name.find("GetTickCount") != string::npos)
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)modGetTickCount, 
					   IARG_FUNCRET_EXITPOINT_REFERENCE,
					   //IARG_RETURN_REGS, 0,
					   IARG_END);
		RTN_Close(rtn);
	}
	else if (routine_name.find("LoadLibrary") != string::npos)
	{
		cout << "HERE" << RTN_Name(rtn) << endl;
	}

}

// This routine is executed for each image.
VOID ImageLoad(IMG img, VOID *)
{
	for(SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		//functions.push_back(make_tuple(SYM_Name(sym), sym));

		if (SYM_Name(sym).find("GetTickCount") != string::npos)
		{

			functions.push_back(make_tuple(SYM_Name(sym), sym));
			cout << SYM_Name(sym) << " IMG: " << IMG_Name(img) <<
				" ADDR: " << hexstr(SYM_Address(sym)) << endl;
		}
	}

    RTN rtn = RTN_FindByName(img, "GetTickCount");
    //cout << "Here\t" <<endl;//<< RTN_Name(rtn) << endl;

    if ( RTN_Valid( rtn ))
    {
		OutFile.flush();
        RTN_Open(rtn);

        RTN_Close(rtn);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
	OutFile.setf(ios::showbase);
    OutFile.close();

    //cout <<  "===============================================" << endl;
    //cout <<  "MyPinTool analysis results: " << endl;
    //cout <<  "Number of instructions: " << insCount  << endl;
    //cout <<  "Number of basic blocks: " << bblCount  << endl;
    //cout <<  "Number of threads: " << threadCount  << endl;
    //cout <<  "===============================================" << endl;
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
        //TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        //PIN_AddThreadStartFunction(ThreadStart, 0);

		RTN_AddInstrumentFunction(Routine, 0);
		//IMG_AddInstrumentFunction(ImageLoad, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
