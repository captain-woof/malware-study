.data
	ssn DWORD 000h
	syscallAddr DWORD 000h

.code
	StageSyscall PROC
		mov ssn, ecx
		ret
	StageSyscall ENDP

	PerformSyscall PROC
		mov r10, ecx
		mov eax, ssn
		syscall
		ret
	PerformSyscall ENDP

	StageIndirectSyscall PROC
		mov ssn, ecx
		mov syscallAddr, edx
		ret
	StageIndirectSyscall ENDP

	PerformIndirectSyscall PROC
		mov r10, ecx
		mov eax, ssn
		jmp syscallAddr
		ret
	PerformIndirectSyscall ENDP
End
