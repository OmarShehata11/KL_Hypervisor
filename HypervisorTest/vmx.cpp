#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "DriverHeader.h"
#include "MemoryHeader.h"
#include "vmxHeader.h"

/* the vm state transition : */
/* vmclear => vmptrld => vmlaunch => VMXOFF => vmresume */
/* you should set up the vmcs field before the vmlaunch */

/* GLOBAL */
PHV_VIRTUAL_MACHINE_STATE  g_pVMState;
ULONG64 g_processCount;

NTSTATUS HvInitVmx()
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	NTSTATUS status;
	// first see if the vmx is supported or not :
	if (!HvIsVmxSupported())
	{
		KdPrint(("[HV]: the vmx is not supported. exit.\n"));
		return STATUS_UNSUCCESSFUL;
	}
	
	// get the process count
	g_processCount = KeQueryActiveProcessorCount(0);
	KdPrint(("[HV]: the active count is : %d\n", g_processCount));

	// allocate space for the global variable
	 g_pVMState = (PHV_VIRTUAL_MACHINE_STATE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HV_VIRTUAL_MACHINE_STATE) * g_processCount, HV_VM_STATE_TAG);
	
	if (g_pVMState == NULL)
	{
		KdPrint(("[HV]: ERROR, can't allocate space for vm state struct.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	KdPrint(("[HV]: allocated pool for the vmstate is done well. \n"));

	// now make it run on every logical process
	KAFFINITY affinity;
	for (int i = 0; i < g_processCount; i++)
	{
		affinity = HvMathPower(2, i);
		KeSetSystemAffinityThread(affinity);

		// here we should now enable the vmx operation from the assembly code
		HvAsmEnableVmx();

		// init the vmcs and vmxon regions
		status = HvAllocateVmxonRegion(&g_pVMState[i]);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] error while init the vmxon region for logical process number : %d\n", i));
		}

		status = HvInitVmcsRegion(&g_pVMState[i]);

		if (!NT_SUCCESS(status))
		{

			KdPrint(("[HV] error while init the vmxon region for logical process number : %d\n", i));
		}
		
		// try to print the location of both vmcs and vmxon regions :

		KdPrint(("[HV]: the location for vmcs region is : 0x%x", g_pVMState[i].VmcsRegion));
		KdPrint(("[HV]: the location for vmxon region is : 0x%x", g_pVMState[i].VmxonRegion));

		KdPrint(("\n==============================================\n"));
	}

	return STATUS_SUCCESS;
}

BOOLEAN HvIsVmxSupported()
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	HV_CPUID_REGISTERS cpuRegisters = { 0 };
	HV_IA32_FEATURE_CONTROL msrRegister = { 0 };

	 

	//static_assert(sizeof(cpuRegisters) == (sizeof(int) * 4), "cpuRegisters has not the same size as 4 int.");

	__cpuid((int*)&cpuRegisters, 1); // the struct will be stored as an array

	//
	// now we need to print out the data from registers ..
	// we need to get the 5th bit from ecx
	//

	if (FlagOn((cpuRegisters.ecx >> 5), 1))
	{
		KdPrint(("[HV]: the vmx bit is set from cpuid. the vmx is supported.\n"));

		// now check for the bits in msr register ia32_feature enable ..
		msrRegister.AllValues = __readmsr(HV_MSR_IA32_FEATURE_CONTROL); // 3BH

		if (msrRegister.Fields.lockBit == 0)
		{
			KdPrint(("[HV] : the lockbit = 0 \n"));

			msrRegister.Fields.vmxEnableOutsideSmx = 1;
			msrRegister.Fields.lockBit = 1; // to disable any further modification to the register ..
			__writemsr(HV_MSR_IA32_FEATURE_CONTROL, msrRegister.AllValues);

		}
		else if(msrRegister.Fields.vmxEnableOutsideSmx == 0) // the EnableVmxon bit
		{
			KdPrint(("[HV]: the lockbit is set already, can't modify the msr register.\n"));
			return FALSE;
		}

		return TRUE;

	}

	KdPrint(("[HV]: VMX is not supported bro.\n"));
	return FALSE;
}

NTSTATUS HvVmxExit()
{
	/* here we should execute the vmxoff instruction and clear allocated memory for regions */

	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	// we should execute vmxoff for every logical processor you have :
	KAFFINITY AffinityMask;
	for (size_t i = 0; i < g_processCount; i++)
	{
		AffinityMask = HvMathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		KdPrint(("\t\t[HV]: Current thread is executing in %d th logical processor.", i));

		if(i != 0)
			__vmx_off();

		// free the space
		MmFreeContiguousMemory(HvFromPhysicalToVirtual(g_pVMState[i].VmxonRegion));
		MmFreeContiguousMemory(HvFromPhysicalToVirtual((g_pVMState[i].VmcsRegion)));

	}


	// then unallocate the pool with tag
	ExFreePoolWithTag(g_pVMState, HV_VM_STATE_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS HvStoreVmPointerIns()
{
	PHYSICAL_ADDRESS PhysicallAdress;
	PhysicallAdress.QuadPart = 0;

	__vmx_vmptrst((unsigned __int64*)&PhysicallAdress.QuadPart);

	if (PhysicallAdress.QuadPart == NULL)
	{
		KdPrint(("[HV] ERROR: can't resolve the address for VMCS address. \n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("[HV]: VMCS address : 0x%x \n", PhysicallAdress.QuadPart));

	return STATUS_SUCCESS;
}


NTSTATUS HvClearVmStateIns(ULONG64 VmcsPhysicalAddress)
{
	int retValue = __vmx_vmclear((unsigned __int64*)&VmcsPhysicalAddress);

	if (retValue) // == 1 OR == 2
	{
		KdPrint(("[HV] ERROR: while executing the vmclear. \n"));
		KdPrint(("[HV]: THE ERROR CODE FROM VMCLEAR is : 1\n"));

		__vmx_off();
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS HvLoadVmStateIns(ULONG64 VmcsPhysicalAddress)
{
	int retValue = __vmx_vmptrld((unsigned __int64*)&VmcsPhysicalAddress);

	if (retValue) // == 1 OR == 2
	{
		KdPrint(("[HV] ERROR: while executing the vmptrld. \n"));
		KdPrint(("[HV]: THE ERROR CODE FROM vmptrld is : 1\n"));

		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

BOOLEAN HvLaunchVm(_In_ int CoreId)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	KdPrint(("\n======================== Launching VM =============================\n"));

	KAFFINITY affinity;

	int i = CoreId;
		affinity = HvMathPower(2, i);
		KeSetSystemAffinityThread(affinity);

		KdPrint(("[HV]: Current thread is executing on the %d th logical core. \n", i));
		
		// now allocate space for the stack that's gonna be used to store values of registers before entering the vm space:
		PVOID StackLocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, HV_STACK_SIZE, HV_STACK_TAG);

		if (StackLocation == NULL)
		{
			KdPrint(("[HV] ERROR: while allocating space for stack. \n"));
			return FALSE;
		}
		KdPrint(("[HV] SUCCESS : the stack is allocated for the %d th process. \n", i));

		// set to the global variable:
		g_pVMState[i].StackAddress = (ULONG64)StackLocation;
	

		// also allocate space for msr bitmap :
		PVOID msrBitmapLocation = MmAllocateNonCachedMemory(PAGE_SIZE);

		if (msrBitmapLocation == NULL)
		{
			KdPrint(("[HV] ERROR: while allocating space for msr Bitmap. \n"));
			return FALSE;
		}
		KdPrint(("[HV] SUCCESS : the msr bitmap is allocated for the %d th process. \n", i));

		RtlZeroMemory(msrBitmapLocation, PAGE_SIZE);

		g_pVMState[i].MsrBitmapVirtual = (ULONG64)msrBitmapLocation;
		g_pVMState[i].MsrBitmapPhysical = HvFromVirtualToPhysical(msrBitmapLocation);


		// now clear the vmstate of the current logical processor :

		NTSTATUS status = HvClearVmStateIns(g_pVMState[i].VmcsRegion);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't clear the vm state. \n"));
			return FALSE;
		}

		// now the vmptrld

		status = HvLoadVmStateIns(g_pVMState[i].VmcsRegion);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't load the address of vm state. \n"));
			return FALSE;
		}

		// now setting up the vmcs fields ..
		KdPrint(("[HV]: SETTING UP THE VMCS FOR PROCESS NUMBER : %d.\n", i));

		status = HvSetUpVmcs(&g_pVMState[i]);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't set up the vmcs. \n"));
			return FALSE;
		}

		// now the vmlaunch, BUT before that, we should save the state of rbp and rsp :
		HvAsmSafeStackState();

		// now execute the vmlaunch
		__vmx_vmlaunch();
		
		//
		// IF THERE'S AN ERROR, WE WILL GET HERE ..
		//
		KdPrint(("[HV] ERROR: couldn't execute the vmlaunch instruction.\n"));

		// now read the error code :
		ULONG64 errorCode;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode); // ONE OF THE VMCS FIELDS
		KdPrint(("[HV]: the error code is %d\n", errorCode));

		// CLOSE THE HYPERVISOR 
		__vmx_off();

		// print the error code :
	//	KdPrint(("[HV] ERROR: error code for vmlaunch is : 0x%x", errorCode));
	//	DbgBreakPoint(); // when I'm going to use the kernel debugging.

		return STATUS_SUCCESS;
}

NTSTATUS HvSetUpVmcs(PHV_VIRTUAL_MACHINE_STATE VmState)
{
	// 
	// at first, we should configure the host segment registers.
	// Note: the purpose of 0xf8 that intel said that the three
	// less significant bits must be cleared (zero).
	//
	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8); 
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	//
	// Next, is the link pointer (used in nested virtualization)
	// no need to use it here, so it's gonna be -1
	//
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	//
	// Some fields are not important to us, but we should configure at as the same of our physical machine
	//
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(HV_MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(HV_MSR_IA32_DEBUGCTL) >> 32);

	//
	// and some other fields, we can ignore them by putting zero into it ..
	//

	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	//
	// configure segment registers based on the gdt base address. 
	// (study GDT and segment registers agaiiinnnnn)
	//
	ULONG64 GdtBase = 0;
	GdtBase = GetGdtBase();

	HvFillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
	HvFillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
	HvFillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
	HvFillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
	HvFillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
	HvFillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
	HvFillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
	HvFillGuestSelectorData((PVOID)GdtBase, TR, GetTr());


	//
	// now it's the GS and FS values in the MSRs:
	//
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(HV_MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(HV_MSR_GS_BASE));
	

	//
	// some unknown fields ..
	//
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 

	//
	// a very important part, from the VM-EXECUTION CONTROL FIELDS.
	// we going to deal with the primary and secodary only.
	// note that the default to all bits is zero, we only need to enable only the bits we are going to need,
	// but remember that some bits are dependent on other bits. 
	//

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, HV_MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_CTL2_RDTSCP , HV_MSR_IA32_VMX_PROCBASED_CTLS2));

	//
	// other control fields going to be ignored, and we do so by putting zero in it.
	//

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, HvAdjustControls(0, HV_MSR_IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, HvAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, HV_MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, HvAdjustControls(VM_ENTRY_IA32E_MODE, HV_MSR_IA32_VMX_ENTRY_CTLS));


	//
	// now the control registers and debug registers.
	//

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	//
	// RFLAGS
	//
	__vmx_vmwrite(GUEST_RFLAGS, GetRflags());
	

	//
	// GDT & IDT for guest, we will use the same as host
	//

	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	//
	// we going to ignore the support for SYSENTER.
	// BUT NOW configure the GDT and IDT but for host
	//
	HV_SEGMENT_SELECTOR SegmentSelector = { 0 };

	HvGetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(HV_MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(HV_MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());


	//
	// now set the RIP, RSP for both guest and host.
	// the rip and rsp for guest will point to the same place, which is the guest memory area.
	// on the other hand, host; the rip will point to a handler that gonna handle the vm exit
	// and choose whether to close the hypervisor or resume.
	//
	__vmx_vmwrite(GUEST_RSP, (ULONG64)VmState->GuestVirtualMemAddress); // setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)VmState->GuestVirtualMemAddress); // setup guest ip

	// we need to know more about why we choosed thisssss.
	__vmx_vmwrite(HOST_RSP, ((ULONG64)VmState->StackAddress+ HV_STACK_SIZE - 1)); // because the stack is reversed, we start from the last address from the stack
	__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);

	return STATUS_SUCCESS;
}


VOID
HvFillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector)
{
	HV_SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            AccessRights;

	HvGetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}


BOOLEAN
HvGetSegmentDescriptor(PHV_SEGMENT_SELECTOR SegmentSelector,
	USHORT            Selector,
	PUCHAR            GdtBase)
{
	PHV_SEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PHV_SEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{ // LA_ACCESSED
		ULONG64 Tmp;
		// this is a TSS or callgate etc, save the base high part
		Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}


ULONG
HvAdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.Fields.High; /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Fields.Low;  /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
	UNREFERENCED_PARAMETER(GuestRegs);
	ULONG ExitReason = 0;
	ULONG64 isSuccess = 0;

	__vmx_vmread(VM_EXIT_REASON, (size_t*)&ExitReason);

	ULONG ExitQualification = 0;
	__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&ExitQualification);

	KdPrint(("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff));
	KdPrint(("\nEXIT_QUALIFICATION 0x%x\n", ExitQualification));


	switch (ExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//


	case EXIT_REASON_HLT:
	{
		KdPrint(("[*] Execution of HLT detected... \n"));

		//
		// that's enough for now ;)
		//
		isSuccess = HvAsmRestoreState();
		if (isSuccess)
		{
			KdPrint(("[HV] SUCCESS: the Restore state worked fine. \n"));
		}

		break;
	}

	default:
	{
		isSuccess = HvAsmRestoreState();
		if (isSuccess)
		{
			KdPrint(("[HV] SUCCESS: the Restore state worked fine from the defualt state bro.... \n"));
		}
		// DbgBreakPoint();
		break;
	}
	}
}


VOID
ResumeToNextInstruction()
{
	PVOID ResumeRIP = NULL;
	PVOID CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, (size_t*)&CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&ExitInstructionLength);

	ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID
VmResumeInstruction()
{
	__vmx_vmresume();

	// if VMRESUME succeeds will never be here !

	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	KdPrint(("[*] VMRESUME Error : 0x%llx\n", ErrorCode));

	//
	// It's such a bad error because we don't where to go!
	// prefer to break
	//
	DbgBreakPoint();
}