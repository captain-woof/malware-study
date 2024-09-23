.code
GetCpuId PROC
	; save non-volatile register on stack
	push rbx

	; move pointer to string to rdi
	mov rdi, rcx

	; set output registers to zero
	mov rbx, 0
	mov rdx, 0
	mov rcx, 0

	; call cpuid with rax set to 0
	mov rax, 40000000h
	cpuid

	; store 4 byte strings from ebx, edx and ecx into pointer stored in rdi
	mov eax, ebx
	stosd
	mov eax, ecx
	stosd
	mov eax, edx
	stosd

	; restore non-volatile register from stack
	pop rbx

	; Return
	ret
GetCpuId ENDP

IsHypervisor2 PROC
	; nullify output register
    mov rcx, 0
    
    ; call cpuid with argument in EAX
    mov rax, 1
    cpuid

	; copy rcx to rax, then extract 31st bit
	mov rax, rcx
	shr rax, 31
    
    ; return from function
    ret
IsHypervisor2 ENDP
END