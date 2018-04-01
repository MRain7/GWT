/*
 * =====================================================================================
 *       Filename:
 *    Description:
 * =====================================================================================
 */

#include<iostream>
#include<string>
#include<stdio.h>
#include<stdlib.h>
#include<fstream>
#include<sstream>
#include<iomanip>       //Streaming Operations such as setw(int);left;right;setprecision(int)
#include<list>
#include<map>
#include"pin.H"
#include"portability.H"
using namespace std;

//==============================================
//commandlines switches
//==============================================

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "DynamicAnalysis.out", "specify profile file name");

//==============================================
//print help message
//==============================================

static INT32 Usage(){
        cerr << "Collects a profile of jump/return/call instructions and traces the gadget information\n";
        cerr << KNOB_BASE::StringKnobSummary();
        cerr << endl;
        return -1;
}

//==============================================
//global variable
//==============================================

//statictical information variables
static UINT32 icount = 0;
//static std::ofstream* out = 0;

class COUNTER{
        public:
            UINT32 _call;
            UINT32 _call_indirect;
            UINT32 _syscall;
            UINT32 _return;
            UINT32 _branch;
            UINT32 _branch_indirect;

            COUNTER(): _call(0), _call_indirect(0), _syscall(0), _return(0), _branch(0), _branch_indirect(0) {}

            UINT32 total(){
                return _call + _call_indirect + _syscall + _return + _branch + _branch_indirect;
            }
};

COUNTER CountSeen;
COUNTER CountTaken;

//##:link two arguments; #:string the argument.
#define INC(what) VOID inc ## what (INT32 taken) { CountSeen. what ++; if(taken) CountTaken. what ++;}
INC(_call)
INC(_call_indirect)
INC(_syscall)
INC(_return)
INC(_branch)
INC(_branch_indirect)

//gadget_trace global variables
//FILE * trace;

char line[1024] = {0};
char buf[20] = {0};
string gadget_type = "";
int gadget_max_len = 0;
int nopgadget_max_len = 0;
string real_gadget_type = "";
string address = "";
string address_target = "";

int num_gadget_function = 0;
int num_gadget_real_function = 0;
int num_gadget_real_nop = 0;
int num_gadget_real_normal = 0;
int num_gadet_total = 0;

int coi = 0;
int coi_peak = 0;
int coi_fun = 1;
int coi_nop = 0;
int max_coi = 8;

int gadget_len = 0;

double taken_IBR = 0.0;
double notaken_IBR = 0.0;

//==============================================
//deal with count info
//=============================================

//total Instruction numbers
VOID docount(){
        icount++;
}

//output format
#define OUT(a,b) cout << a << setw(16) << CountSeen.b << " " << setw(16) << CountTaken.b << endl

//==============================================
//deal with gadget_trace
//=============================================

void clear(){
    //line[1024] = {0};   //C++11 property
    memset(line,0,strlen(line));
    memset(buf,0,strlen(buf));
    gadget_type = "";
    gadget_max_len = 0;
    nopgadget_max_len = 0;
    real_gadget_type = "";
    address = "";
}

void indirect_branch(UINT32 insaddr, string insDis){
    //address_target = (string)insaddr; // false format, so use sprintf to transform int --> char []
    sprintf(buf, "%x",insaddr);
    //it is ok that char[] --> string, PS: //printf("address_target:    %s\n", address_target.c_str());
    address_target = buf;

    //loop txt to infoimation about gadget
    ifstream fin("static_results.txt", ios::in);
    while(fin.getline(line, sizeof(line))){
        istringstream word(line);
        word >> address >> gadget_type >> gadget_max_len >> nopgadget_max_len;
        if(address == address_target){
            taken_IBR++;
            //cout << "equal:  " << address << "  type:  " << gadget_type << "  max_len:  " << gadget_max_len << "  nop_max_len  " << nopgadget_max_len << "  gadget_len:  " << gadget_len << endl;
            break;
        }
        else{
            //to avoid the former loop information influence.
            clear();
        }
    }

    if(address == ""){
        notaken_IBR++;
        cout << "There is not information about this IBR, addres:  " << address_target << "  INS:  " << insDis << endl;
    }

    if(gadget_type == "Functional"){
        num_gadget_function++;
    }

    //judge the real_gadget_type
    if(gadget_type == "NOP"){
        if(gadget_len <= nopgadget_max_len){
            real_gadget_type = "NOP";
        }
        else{
            real_gadget_type = "Normal";
        }
    }
    else if(gadget_type == "Functional"){
        if(gadget_len <= gadget_max_len){
            real_gadget_type = "Functional";
        }
        else if(gadget_len <= nopgadget_max_len){
            real_gadget_type = "NOP";
        }
        else{
            real_gadget_type = "Normal";
        }
    }
    else{
        real_gadget_type = "Normal";
    }

    gadget_len = 0;

    //judge whether occour the attack
    if(real_gadget_type == "Normal"){
        num_gadget_real_normal++;
        if(coi > coi_peak){
            coi_peak = coi;
        }
        coi = 0;
    }
    else if(real_gadget_type == "Functional"){
        num_gadget_real_function++;
        coi += coi_fun;
    }
    else if(real_gadget_type == "NOP"){
        num_gadget_real_nop++;
        coi += coi_nop;
    }
    if(coi > max_coi){
        cout << "occour an attack!!! kill the program" << endl;
    }

    if(real_gadget_type != "Normal"){
        //cout << endl;
        //cout << "real_gadget_type:   " << real_gadget_type << "  coi:   " << coi << "  max_coi:   " << max_coi <<endl;
        //cout << endl;
    }

    clear();
    fin.clear();
    fin.close();
}

//===========================================
//PIN API function
//===========================================

void Instruction(INS ins, void *v){
    //total Instruction numbers
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount, IARG_END);
    if(INS_IsRet(ins)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_return, IARG_BRANCH_TAKEN, IARG_END);
    }
    else if(INS_IsSyscall(ins)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_syscall, IARG_BRANCH_TAKEN, IARG_END);
    }
    else if(INS_IsDirectBranchOrCall(ins)){
        if(INS_IsCall(ins))
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_call, IARG_BRANCH_TAKEN, IARG_END);
        else
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_branch, IARG_BRANCH_TAKEN, IARG_END);
        }
    else if(INS_IsIndirectBranchOrCall(ins)){
        if(INS_IsCall(ins))
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_call_indirect, IARG_BRANCH_TAKEN, IARG_END);
        else
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_branch_indirect, IARG_BRANCH_TAKEN, IARG_END);
    }

    //gadget_trace
    gadget_len++;
    if(INS_IsIndirectBranchOrCall(ins)){
        //indirect_branch(INS_Address(ins));
        INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)indirect_branch,
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_PTR, new string (INS_Disassemble(ins)),
                       IARG_END);
    }
}

void Fini(INT32 code, void *v){
    //absolute reference
    SetAddress0x(1);
    cout << "********************Instructions Information:**********************\n" << endl;
    cout << "===============================================================\n";
    cout << "total_instruction: " << icount << endl;
    cout << "result display  " << setw(16) << "Seen" << setw(16) <<"Taken" << endl;
    OUT("call            ", _call);
    OUT("indirect_call   ", _call_indirect);
    OUT("syscall         ", _syscall);
    OUT("return          ", _return);
    OUT("branch          ", _branch);
    OUT("indirect_branch ", _branch_indirect);
    cout << "total_branch    " << setw(16) << CountSeen.total() << " " << setw(16) << CountTaken.total() << endl;
    cout << "===============================================================\n";

    //deal with Instruction data
    //cout << "total_branch_seen  / total_instruction = " << ((double)CountSeen.total()/(double)icount) << endl;
    cout << "total_branch_taken / total_instruction = " << ((double)CountTaken.total()/(double)icount) << endl;
    //cout << "IBR_seen  /  BR_seen = " << ((double)(CountSeen._call_indirect + CountSeen._branch_indirect + CountSeen._syscall + CountSeen._return) / (double)CountSeen.total())<< endl;
    cout << "IBR_taken / BR_taken = " << ((double)(CountTaken._call_indirect + CountTaken._branch_indirect + CountTaken._syscall + CountTaken._return) / (double)CountTaken.total()) << endl;
    //cout << "IBR_seen  /  total_instruction = " << ((double)(CountSeen._call_indirect + CountSeen._branch_indirect + CountSeen._syscall + CountSeen._return) / (double)icount)<< endl;
    cout << "IBR_taken / total_instruction  = " << ((double)(CountTaken._call_indirect + CountTaken._branch_indirect + CountTaken._syscall + CountTaken._return) / (double)icount) << endl;

    cout << endl;
    //out->close();

    //output gadget_trace data in terminal
    cout << "********************gadget_trace information:**********************\n" << endl;
    cout << "taken_IBR / total_IBR = " << taken_IBR/(taken_IBR+notaken_IBR) << endl;
    cout << "num_gadget_function: " << num_gadget_function << endl;
    cout << "num_gadget_real_function: " << num_gadget_real_function << endl;
    cout << "num_gadget_real_nop: " << num_gadget_real_nop << endl;
    cout << "num_gadget_real_normal: " << num_gadget_real_normal << endl;
    cout << "coi_peak: " << coi_peak << endl;
}

int main(int argc, char *argv[]){
    if(PIN_Init(argc,argv))
        return Usage();

    //string filename = KnobOutputFile.Value();
    //out = new std::ofstream(filename.c_str());

    int argunum;
    for(argunum = 0; argunum < argc; argunum++){
        if((std::string)argv[argunum] == "--"){
            cout << "TARGET:\t" << argv[argunum+1] <<endl;
        }
    }

    INS_AddInstrumentFunction(Instruction,0);
    PIN_AddFiniFunction(Fini,0);
    PIN_StartProgram();

    return 0;
}

//===============================================
//EOF
//==============================================
