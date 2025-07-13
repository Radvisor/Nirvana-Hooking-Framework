#pragma once

#include <atomic>
#include <vector>
#include <shared_mutex>


#ifdef _WIN64
	struct SyscallData
	{
		QWORD ReturnValue;	// rax
		QWORD FirstArg;		// rcx
		QWORD SecondArg;	// rdx
		QWORD ThirdArg;		// r8
		QWORD FourthArg;	// r9
		QWORD CallerAddr;	// r10
	};
	using PSyscallData = SyscallData*;
#else
	struct SyscallData
	{
		DWORD ReturnValue;	// eax
		DWORD CallerAddr;	// eip
	};
	using PSyscallData = SyscallData*;
#endif


class NirvanaHookingTable
{
	public:
		NirvanaHookingTable();
		~NirvanaHookingTable();
		
		VOID HighCallbackWrapper( QWORD );
		
		VOID AddHook( CallbackHook& chHook );
		VOID RemHook( CallbackHook& chHook );
	
	private:
		thread_local std::atomic<BOOL> bIsRecursing = FALSE;
		std::vector<CallbackHook*> vHookList;
		mutable std::shared_mutex mHookListMutex;
};

class CallbackHook
{
	public:
		CallbackHook( LPCSTR pszFuncName ) : pszHookedFunc(pszFuncName) {}
		
		LPCSTR GetName() const {return pszHookedFunc;}
		PSyscallData GetSyscallDataPtr() {return &sdRegValues;}
		
		virtual VOID HookRoutine() = 0;
		
	private:
		LPCSTR pszHookedFunc = nullptr;
		SyscallData sdRegValues = { 0 };
};