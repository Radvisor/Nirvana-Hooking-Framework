#include <windows.h>

#include "NirvanaHooking.h"

#include <cstdint>
#include <system_error>
#include <shared_mutex>


using std::system_error;
using std::error_code;
using std::system_category;


#pragma comment(lib, "ntdll.lib")

/*
  Undocumented function ( see: https://ntdoc.m417z.com/ntsetinformationprocess ).
*/
extern "C" NTSYSAPI NTSTATUS NTAPI NtSetInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
);

/*
  Undocumented internal structure ( see: https://ntdoc.m417z.com/process_instrumentation_callback_information ).
*/
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;	// Current process architecture: set to 0 if x64 / to 1 if x86
	ULONG Reserved;	// Always 0
	PVOID Callback;	// Address of the callback function
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

/*
  Undocumented value of the PROCESSINFOCLASS enum ( see: https://ntdoc.m417z.com/processinfoclass ).
*/
using EnumSize_t = std::uint_least_t<sizeof(PROCESSINFOCLASS) * 8>::type;
constexpr EnumSize_t ProcessInstrumentationCallback = 40;


extern "C"
{
/*
  Our assembly function which will be the first code executed in the context of the callback.
*/
#ifdef _WIN64
	VOID LowCallbackWrapper64();
#else
	VOID LowCallbackWrapper32();
#endif
}


class ScopedSymbols
{
	public:
		explicit ScopedSymbols()
		{
			hDbghelpDll = LoadLibraryW(L"Dbghelp.dll");
			if( !hDbghelpDll )
				throw system_error( error_code(GetLastError(), system_category()), "Failed to load Dbghelp.dll" );
			
			bAreSymbolsSet = SymInitialize(GetCurrentProcess(), nullptr, TRUE);
			if( !bAreSymbolsSet )
			{
				FreeLibrary(hDbghelpDll);
				throw system_error( error_code(GetLastError(), system_category()), "Failed to set up symbols" );
			}
		}

		ScopedSymbols(const ScopedSymbols&) = delete;
		ScopedSymbols& operator = (const ScopedSymbols&) = delete;

		~ScopedSymbols() noexcept
		{
			if(bAreSymbolsSet) SymCleanup(GetCurrentProcess());
			if(hDbghelpDll) FreeLibrary(hDbghelpDll);
		}
	
	private:
		HMODULE hDbghelpDll = nullptr;
		BOOL bAreSymbolsSet = FALSE;
};


NirvanaHookingTable::NirvanaHookingTable()
{
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION piciCallbackInfo = { 0 };
	NTSTATUS ntsSetIC;

	try{ ScopedSymbols ssDebugSymbols; }
	catch(...) {
		throw;
	}
	
#	ifndef _WIN64
		piciCallbackInfo.Version = 1;
		piciCallbackInfo.Callback = CallbackWrapper32;
#	else
		piciCallbackInfo.Callback = CallbackWrapper64;
#	endif
	ntsSetIC = NtSetInformationProcess( GetCurrentProcess(), ProcessInstrumentationCallback, &piciCallbackInfo, sizeof(piciCallbackInfo) );
	if( NT_ERROR(ntsSetIC) )
		throw system_error( error_code(ntsSetIC, system_category()), "Failed to set up the instrumentation callback" );
}

NirvanaHookingTable::~NirvanaHookingTable()
{
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION piciCallbackInfo = { 0 };
	
#	ifndef _WIN64
		piciCallbackInfo.Version = 1;
#	endif
	piciCallbackInfo.Callback = nullptr;
	NtSetInformationProcess( GetCurrentProcess(), ProcessInstrumentationCallback, &piciCallbackInfo, sizeof(piciCallbackInfo) );
}

/*
	Our higher level function our assembly code will pass control to.
	Check the definition of SyscallData in NirvanaHooking.h to see what register corresponds to what data.
	
	Also, comparing the name of each hook with the syscall symbol adds A LOT of overhead, but it works
	(I would recommend using a hash table instead).
*/
#ifdef _WIN64
	VOID NirvanaHookingTable::HighCallbackWrapper( QWORD rax, QWORD rcx, QWORD rdx, QWORD r8, QWORD r9, QWORD r10 )
	{
		if( this->bIsRecursing )
			return;
		
		CHAR szSymInfo[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO psiSymInfo = NULL;
		
		this->bIsRecursing = TRUE;
		
		psiSymInfo = (PSYMBOL_INFO)szSymInfo;
		psiSymInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
		psiSymInfo.MaxNameLen = MAX_SYM_NAME;
		if( !SymFromAddr( GetCurrentProcess(), r10, 0, psiSymInfo ) )
		{
			this->bIsRecursing = FALSE;
			return;
		}
		
		std::unique_lock lock(this->mHookListMutex);
		
		for (auto& hook : vHookList) {
			if( strcmp(psiSymInfo.Name, hook.pszHookedFunc) == 0 )
			{
				PSyscallData psdRegValues = hook.GetSyscallDataPtr();
				
				psdRegValues->ReturnValue = rax;
				psdRegValues->FirstArg = rcx;
				psdRegValues->SecondArg = rdx;
				psdRegValues->ThirdArg = r8;
				psdRegValues->FourthArg = r9;
				psdRegValues->CallerAddr = r10;
				
				hook.HookRoutine();
				break;
			}
		}

		this->bIsRecursing = FALSE;
	}
#else
	VOID NirvanaHookingTable::HighCallbackWrapper( DWORD eax, DWORD eip )
	{
		if( this->bIsRecursing )
			return;
		
		CHAR szSymInfo[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO psiSymInfo = NULL;
		
		this->bIsRecursing = TRUE;
		
		psiSymInfo = (PSYMBOL_INFO)szSymInfo;
		psiSymInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
		psiSymInfo.MaxNameLen = MAX_SYM_NAME;
		if( !SymFromAddr( GetCurrentProcess(), eip, 0, psiSymInfo ) )
		{
			this->bIsRecursing = FALSE;
			return;
		}
		
		std::unique_lock lock(this->mHookListMutex);
		
		for (auto& hook : vHookList) {
			if( strcmp(psiSymInfo.Name, hook.pszHookedFunc) == 0 )
			{
				PSyscallData psdRegValues = hook.GetSyscallDataPtr();
				
				psdRegValues->ReturnValue = eax;
				psdRegValues->CallerAddr = eip;
				
				hook.HookRoutine();
				break;
			}
		}

		this->bIsRecursing = FALSE;
	}
#endif

VOID NirvanaHookingTable::AddHook( CallbackHook& chHook )
{
	std::unique_lock lock(this->mHookListMutex);
	
	for( size_t i = 0; i < this->vHookList.size(); i++ )
	{
		if( strcmp( chHook->GetName(), this->vHookList[i]->GetName() ) == 0 )
		{
			this->vHookList.erase(this->vHookList.begin() + i);
			break;
		}
	}
	this->vHookList.push_back(&chHook);
}

VOID NirvanaHookingTable::RemHook( CallbackHook& chHook )
{
	std::unique_lock lock(this->mHookListMutex);
	
	for( size_t i = 0; i < this->vHookList.size(); i++ )
	{
		if( &chHook == vHookList[i] )
		{
			this->vHookList.erase(this->vHookList.begin() + i);
			break;
		}
	}
}
