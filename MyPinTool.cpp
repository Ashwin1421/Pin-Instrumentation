/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */


/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 * 	@author
 * 	Ashwin Joshi, avj160330@utdallas.edu
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <vector>
#include <iomanip>
#include <unistd.h>
#include "control_manager.H"
//task-2
#if defined(TARGET_MAC) || defined(TARGET_BSD) || defined(TARGET_ANDROID)
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif

#ifdef TARGET_ANDROID
#define SYS_mmap __NR_mmap
#endif
/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif



using namespace CONTROLLER; //for task-3 i.e counting executions for an instruction.

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread


std::ostream * out = &cerr;

static std::ofstream* sol1 = new std::ofstream("soln-1.out");
static std::ofstream* sol2 = new std::ofstream("soln-2.out");
static std::ofstream* sol3 = new std::ofstream("soln-3.out");
static std::ofstream* sol4 = new std::ofstream("soln-4.out");
static std::ofstream* sol5 = new std::ofstream("soln-5.out");
static std::ofstream* sol6 = new std::ofstream("soln-6.out");


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments ");
KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
/* Commandline Switches specific to task-3 */
/* Not omitted from this instrumentation.  */
/* ===================================================================== */

KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "0", "append pid to output");
KNOB<BOOL>   KnobProfilePredicated(KNOB_MODE_WRITEONCE,  "pintool",
    "p", "0", "enable accurate profiling for predicated instructions");
KNOB<BOOL>   KnobProfileStaticOnly(KNOB_MODE_WRITEONCE,  "pintool",
    "s", "0", "terminate after collection of static profile for main image");
#ifndef TARGET_WINDOWS
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "0", "Only collect dynamic profile");
#else
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "1", "Only collect dynamic profile");
#endif
KNOB<BOOL>   KnobNoSharedLibs(KNOB_MODE_WRITEONCE,       "pintool",
    "no_shared_libs", "0", "do not instrument shared libraries");

/* ===================================================================== */
/* INDEX HELPERS for task - 3. */
/* ===================================================================== */

const UINT32 MAX_INDEX = 4096;
const UINT32 INDEX_SPECIAL =  3000;
const UINT32 MAX_MEM_SIZE = 512;


const UINT32 INDEX_TOTAL =          INDEX_SPECIAL + 0;
const UINT32 INDEX_MEM_ATOMIC =     INDEX_SPECIAL + 1;
const UINT32 INDEX_STACK_READ =     INDEX_SPECIAL + 2;
const UINT32 INDEX_STACK_WRITE =    INDEX_SPECIAL + 3;
const UINT32 INDEX_IPREL_READ =     INDEX_SPECIAL + 4;
const UINT32 INDEX_IPREL_WRITE =    INDEX_SPECIAL + 5;
const UINT32 INDEX_MEM_READ_SIZE =  INDEX_SPECIAL + 6;
const UINT32 INDEX_MEM_WRITE_SIZE = INDEX_SPECIAL + 6 + MAX_MEM_SIZE;
const UINT32 INDEX_SPECIAL_END   =  INDEX_SPECIAL + 6 + MAX_MEM_SIZE + MAX_MEM_SIZE;



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
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
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
 
 
// Function called to calculate no of instructions within a specific image.
// Task - 2
VOID ImageLoad(IMG img, VOID *v)
{
    UINT64 count = 0;
    
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    { 
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs 
            RTN_Open(rtn);
            
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
               	count++;
            }

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }
    
	*sol2 << "Image: " << IMG_Name(img).c_str() << endl;
	*sol2 << "No. of instructions: " << count << endl;
	*sol2 << "===============================================" << endl;
}

/*=============================  TASK-3 Start  ====================================*/
/*
 *	All helper routines for task-3 included here.
 *  Referred opcodemix.cpp for this implementation.
 */
BOOL IsMemReadIndex(UINT32 i)
{
    return (INDEX_MEM_READ_SIZE <= i && i < INDEX_MEM_READ_SIZE + MAX_MEM_SIZE );
}

BOOL IsMemWriteIndex(UINT32 i)
{
    return (INDEX_MEM_WRITE_SIZE <= i && i < INDEX_MEM_WRITE_SIZE + MAX_MEM_SIZE );
}


/* ===================================================================== */

LOCALFUN UINT32 INS_GetIndex(INS ins)
{
    if( INS_IsPredicated(ins) )
        return MAX_INDEX + INS_Opcode(ins);
    else
        return INS_Opcode(ins);
}

/* ===================================================================== */

LOCALFUN  UINT32 IndexStringLength(BBL bbl, BOOL memory_acess_profile)
{
    UINT32 count = 0;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
        count++;
        if( memory_acess_profile )
        {
            if( INS_IsMemoryRead(ins) ) count++;   // for size

            if( INS_IsStackRead(ins) ) count++;

            if( INS_IsIpRelRead(ins) ) count++;


            if( INS_IsMemoryWrite(ins) ) count++; // for size

            if( INS_IsStackWrite(ins) ) count++;

            if( INS_IsIpRelWrite(ins) ) count++;


            if( INS_IsAtomicUpdate(ins) ) count++;
        }
    }

    return count;
}


/* ===================================================================== */
LOCALFUN UINT32 MemsizeToIndex(UINT32 size, BOOL write)
{
    return (write ? INDEX_MEM_WRITE_SIZE : INDEX_MEM_READ_SIZE ) + size;
}

/* ===================================================================== */
LOCALFUN UINT16 *INS_GenerateIndexString(INS ins, UINT16 *stats, BOOL memory_acess_profile)
{
    *stats++ = INS_GetIndex(ins);

    if( memory_acess_profile )
    {
        if( INS_IsMemoryRead(ins) )  *stats++ = MemsizeToIndex( INS_MemoryReadSize(ins), 0 );
        if( INS_IsMemoryWrite(ins) ) *stats++ = MemsizeToIndex( INS_MemoryWriteSize(ins), 1 );

        if( INS_IsAtomicUpdate(ins) ) *stats++ = INDEX_MEM_ATOMIC;

        if( INS_IsStackRead(ins) ) *stats++ = INDEX_STACK_READ;
        if( INS_IsStackWrite(ins) ) *stats++ = INDEX_STACK_WRITE;

        if( INS_IsIpRelRead(ins) ) *stats++ = INDEX_IPREL_READ;
        if( INS_IsIpRelWrite(ins) ) *stats++ = INDEX_IPREL_WRITE;
    }

    return stats;
}


/* ===================================================================== */

LOCALFUN string IndexToOpcodeString( UINT32 index )
{
    if( INDEX_SPECIAL <= index  && index < INDEX_SPECIAL_END)
    {
        if( index == INDEX_TOTAL )            return  "*total";
        else if( IsMemReadIndex(index) )      return  "*mem-read-" + decstr( index - INDEX_MEM_READ_SIZE );
        else if( IsMemWriteIndex(index))      return  "*mem-write-" + decstr( index - INDEX_MEM_WRITE_SIZE );
        else if( index == INDEX_MEM_ATOMIC )  return  "*mem-atomic";
        else if( index == INDEX_STACK_READ )  return  "*stack-read";
        else if( index == INDEX_STACK_WRITE ) return  "*stack-write";
        else if( index == INDEX_IPREL_READ )  return  "*iprel-read";
        else if( index == INDEX_IPREL_WRITE ) return  "*iprel-write";

        else
        {
            ASSERTX(0);
            return "";
        }
    }
    else
    {
        return OPCODE_StringShort(index);
    }

}

/* ===================================================================== */
/* ===================================================================== */
typedef UINT64 COUNTER;


/* zero initialized */

class STATS
{
  public:
    COUNTER unpredicated[MAX_INDEX];
    COUNTER predicated[MAX_INDEX];
    COUNTER predicated_true[MAX_INDEX];

    VOID Clear()
    {
        for ( UINT32 i = 0; i < MAX_INDEX; i++)
        {
            unpredicated[i] = 0;
            predicated[i] = 0;
            predicated_true[i] = 0;
        }
    }
};


STATS GlobalStatsStatic;
STATS GlobalStatsDynamic;

class BBLSTATS
{
  public:
    COUNTER _counter;
    const UINT16 * const _stats;

  public:
    BBLSTATS(UINT16 * stats) : _counter(0), _stats(stats) {};

};



LOCALVAR vector<const BBLSTATS*> statsList;



/* ===================================================================== */

LOCALVAR UINT32 enabled = 0;

LOCALFUN VOID Handler(EVENT_TYPE ev, VOID *val, CONTEXT * ctxt, VOID *ip, THREADID tid, bool bcast)
{
    switch(ev)
    {
      case EVENT_START:
        enabled = 1;
        break;

      case EVENT_STOP:
        enabled = 0;
        break;

      default:
        ASSERTX(false);
    }
}


LOCALVAR CONTROL_MANAGER control;

/* ===================================================================== */

VOID PIN_FAST_ANALYSIS_CALL docount(COUNTER * counter)
{
    (*counter) += enabled;
}

/* ===================================================================== */

/*============================= Task-4 Start ====================================*/

string invalid = "invalid_rtn";

const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}

/* ===================================================================== */

VOID  do_call_args(const string *s, ADDRINT arg0)
{
    *sol4 << *s << "(" << arg0 << ",...)" << endl;
}

/* ===================================================================== */

VOID  do_call_args_indirect(ADDRINT target, BOOL taken, ADDRINT arg0)
{
    if( !taken ) return;
    
    const string *s = Target2String(target);
    do_call_args(s, arg0);

    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID  do_call(const string *s)
{
    *sol4 << *s << endl;
}

/* ===================================================================== */

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
    if( !taken ) return;

    const string *s = Target2String(target);
    do_call( s );
    
    if (s != &invalid)
        delete s;
}




/*============================= Task-4 End ======================================*/


VOID Trace(TRACE trace, VOID *v)
{
    if ( KnobNoSharedLibs.Value()
         && IMG_Type(SEC_Img(RTN_Sec(TRACE_Rtn(trace)))) == IMG_TYPE_SHAREDLIB)
        return;

	const BOOL print_args = KnobPrintArgs.Value();

    const BOOL accurate_handling_of_predicates = KnobProfilePredicated.Value();

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        const INS head = BBL_InsHead(bbl);
        if (! INS_Valid(head)) continue;
		
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
		
		
		INS tail = BBL_InsTail(bbl);
		
		
		//=================================task-4 instrumentation start========================================
		
		        if( INS_IsCall(tail) )
        {
            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                if( print_args )
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_PTR, Target2String(target), IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_PTR, Target2String(target), IARG_END);
                }
                
            }
            else
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
                
                
            }
        }
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

                }
            }
        }
		//=================================task-4 instrumentation end  ========================================
		
        // Summarize the stats for the bbl in a 0 terminated list
        // This is done at instrumentation time
        const UINT32 n = IndexStringLength(bbl, 1);

        UINT16 *const stats = new UINT16[ n + 1];
        UINT16 *const stats_end = stats + (n + 1);
        UINT16 *curr = stats;

        for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
        {
            // Count the number of times a predicated instruction is actually executed
            // this is expensive and hence disabled by default
            if( INS_IsPredicated(ins) && accurate_handling_of_predicates )
            {
                INS_InsertPredicatedCall(ins,
                                         IPOINT_BEFORE,
                                         AFUNPTR(docount),
                                         IARG_PTR, &(GlobalStatsDynamic.predicated_true[INS_Opcode(ins)]),
                                         IARG_END);
            }

            curr = INS_GenerateIndexString(ins,curr,1);
        }

        // string terminator
        *curr++ = 0;

        ASSERTX( curr == stats_end );


        // Insert instrumentation to count the number of times the bbl is executed
        BBLSTATS * bblstats = new BBLSTATS(stats);
        INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(bblstats->_counter), IARG_END);

        // Remember the counter and stats so we can compute a summary at the end
        statsList.push_back(bblstats);
    }
}

/* ===================================================================== */
VOID DumpStats(ofstream& sol3, STATS& stats, BOOL predicated_true,  const string& title)
{


    sol3 <<
        "#\n"
        "# " << title << "\n"
        "#\n"
        "#     opcode       count-unpredicated    count-predicated";

    if( predicated_true )
        sol3 << "    count-predicated-true";

    sol3 << "\n#\n";

    for ( UINT32 i = 0; i < INDEX_TOTAL; i++)
    {
        stats.unpredicated[INDEX_TOTAL] += stats.unpredicated[i];
        stats.predicated[INDEX_TOTAL] += stats.predicated[i];
        stats.predicated_true[INDEX_TOTAL] += stats.predicated_true[i];
    }

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        if( stats.unpredicated[i] == 0 &&
            stats.predicated[i] == 0 ) continue;

        sol3 << setw(4) << i << " " <<  ljstr(IndexToOpcodeString(i),15) << " " <<
            setw(16) << stats.unpredicated[i] << " " <<
            setw(16) << stats.predicated[i];
        if( predicated_true ) sol3 << " " << setw(16) << stats.predicated_true[i];
        sol3 << endl;
    }
}





/*=============================  TASK-3 End  ====================================*/

// =================================== Task - 6 Start =================================

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
               ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_IA32) 
    // On ia32, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = &arg0;
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

	switch(num) {
		
		case 0:
				*sol6 << "@ip 0x" << hex << ip << ": sys call restart_syscall with number= " << dec << num << endl;
				break;
		case 1:
				*sol6 << "@ip 0x" << hex << ip << ": sys call exit with number= " << dec << num << endl;
				break;
		case 2:
				*sol6 << "@ip 0x" << hex << ip << ": sys call fork with number= " << dec << num << endl;
				break;
		case 3:
				*sol6 << "@ip 0x" << hex << ip << ": sys call read with number= " << dec << num << endl;
				break;
		case 4:
				*sol6 << "@ip 0x" << hex << ip << ": sys call write with number= " << dec << num << endl;
				break;
		case 5:
				*sol6 << "@ip 0x" << hex << ip << ": sys call open with number= " << dec << num << endl;
				break;
		case 6:
				*sol6 << "@ip 0x" << hex << ip << ": sys call close with number= " << dec << num << endl;
				break;
		case 7:
				*sol6 << "@ip 0x" << hex << ip << ": sys call waitpid with number= " << dec << num << endl;
				break;
		case 8:
				*sol6 << "@ip 0x" << hex << ip << ": sys call creat with number= " << dec << num << endl;
				break;
		case 9:
				*sol6 << "@ip 0x" << hex << ip << ": sys call link with number= " << dec << num << endl;
				break;
		case 10:
				*sol6 << "@ip 0x" << hex << ip << ": sys call unlink with number= " << dec << num << endl;
				break;
		default:
				*sol6 << "@ip 0x" << hex << ip << ": sys call " << dec << num;
				*sol6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
			    *sol6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
	}

}


// Print the return value of the system call
VOID SysAfter( ADDRINT value, INT32 err, UINT32 gax )
{
    int error = 0;
    ADDRINT neg_one = (ADDRINT)(0-1);
    
    if ( err == 0 ) 
    {
        if ( gax != value )
            error = 1;
    }
    else
    {
        if ( value != neg_one )
            error = 3;
        if ( err != -(INT32)gax )
            error = 4;
    }

    if ( error == 0 )
        *sol6 << "Success: value=0x" << hex << value << ", errno=" << dec << err << endl;
    else 
    {
        *sol6 << "Failure " << error << ": value=0x" << hex << value << ", errno=" << dec << err;
        *sol6 << ", gax=0x" << hex << gax << endl;
    }
    
    *sol6 << endl;
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std),
             PIN_GetSyscallErrno(ctxt, std),
             PIN_GetContextReg(ctxt, REG_GAX));
}

static UINT64 icount = 0;

VOID docount () { icount++; }
// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);
        
        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE, IARG_SYSRET_ERRNO,
                       IARG_REG_VALUE, REG_GAX,
                       IARG_END);
    }
}


// =================================== Task - 6 End   =================================


VOID Fini(INT32 code, VOID *v)
{
	

    *sol1 <<  "===============================================" << endl;
    *sol1 <<  "Task 1: " << endl;
    *sol1 <<  "====Dynamically executed instructions==========" << endl;
    *sol1 <<  "Number of instructions: " << icount  << endl;
    *sol1 <<  "===============================================" << endl;
    
    
    // Task-3 function calls.
    // static counts


	*sol3 << "==========================================================" << endl;
	*sol3 << "Task-3: No. of executions per instruction encountered." << endl;
	*sol3 << "==========================================================" << endl;

    DumpStats(*sol3, GlobalStatsStatic, false, "$static-counts");

    *sol3 << endl;

    // dynamic Counts

    statsList.push_back(0); // add terminator marker

    for (vector<const BBLSTATS*>::iterator bi = statsList.begin(); bi != statsList.end(); bi++)
    {
        const BBLSTATS *b = (*bi);

        if ( b == 0 ) continue;

        for (const UINT16 * stats = b->_stats; *stats; stats++)
        {
            GlobalStatsDynamic.unpredicated[*stats] += b->_counter;
        }
    }


    DumpStats(*sol3, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts");

    *sol3 << "# $eof" <<  endl;

    sol3->close();
    
    
    //=====================task-4=========================================================
    
    *sol4 << "#eof" << endl;
    sol4->close();
    
    //====================task - 5 ================================================

    sol5->close();
    
    
    //=====================task - 6 ====================================================
    *sol6 << "#eof" << endl;
    sol6->close();
}


/* ===================================================================== */

// ========================== Task - 5 Start =========================================
/* ===================================================================== */

VOID Arg1Before(CHAR * name, ADDRINT size)
{
    *sol5 << name << "(" << size << ")" << endl;
}

/* ===================================================================== */

VOID MallocAfter(ADDRINT ret)
{
    *sol5 << "  returns " << ret << endl;
}

/* ===================================================================== */

// ========================== Task - 5 End   =========================================

VOID Image(IMG img, VOID * v)
{

	//==================== Task - 5 Part ===============================================================================
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	
	if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, MALLOC, IARG_G_ARG0_CALLEE, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_G_RESULT0, IARG_END);
        RTN_Close(mallocRtn);
    }
    
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, FREE, IARG_G_ARG0_CALLEE, IARG_END);
        RTN_Close(freeRtn);
    }
    //===================================================================================================================
	
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                UINT16 array[128];
                UINT16 *end  = INS_GenerateIndexString(ins,array,1);

                if( INS_IsPredicated(ins) )
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.predicated[ *start ]++;
                }
                else
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.unpredicated[ *start ]++;
                }
            }

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }

    if( KnobProfileStaticOnly.Value() )
    {
        Fini(0,0);
        exit(0);
    }
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
    
    //Preparing for image instrumentation mode
	PIN_InitSymbols();
	
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    //Task-3 controls
    control.RegisterHandler(Handler, 0, FALSE);
    control.Activate();
    
    /*sol4.open(KnobOutputFile.Value().c_str());
    *sol4 << hex;
    *sol4.setf(ios::showbase);*/
    
    *sol4 << "==========================================================" << endl;
    *sol4 << "Task - 4" << endl;
    *sol4 << "==========================================================" << endl;
    /*string trace_header = string("#\n"
    							 "# Call trace generated by PIN\n"
    							 "#\n");
   	*sol4.write(trace_header.c_str(), trace_header.size());*/
    
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}
    
    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);
	

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

		
    	*sol2 << "Task 2: Image Analysis" << endl;
		*sol2 << "===============================================" << endl;
		
		// Register ImageLoad to be called when an image is loaded
		IMG_AddInstrumentFunction(ImageLoad, 0); 

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
        
        *sol5 << "================================================================" << endl;
    	*sol5 << "Task - 5: " << endl;    
    	*sol5 << "================================================================" << endl;
        
        
        if( !KnobProfileDynamicOnly.Value() )
        	IMG_AddInstrumentFunction(Image, 0);
        	
        	
        *sol6 << "================================================================" << endl;
        *sol6 << "Task - 6: " << endl;
        *sol6 << "================================================================" << endl;
		
		INS_AddInstrumentFunction(Instruction, 0);
    	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    	PIN_AddSyscallExitFunction(SyscallExit, 0);
		
    }
   
    
    cerr <<  "======================================================================" << endl;
    cerr <<  "This application is instrumented as a modification of the MyPinTool." << endl;
    cerr <<  "Author: Ashwin Joshi, avj160330@utdallas.edu." << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "======================================================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
