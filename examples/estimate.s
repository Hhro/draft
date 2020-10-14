	.file	"test.c"
	.intel_syntax noprefix
	.text
	.globl	div
	.type	div, @function
div:
	push	rbp
	mov	rbp, rsp
	mov	DWORD PTR -4[rbp], edi
	mov	DWORD PTR -8[rbp], esi
	mov	eax, DWORD PTR -4[rbp]
	cdq
	idiv	DWORD PTR -8[rbp]
	pop	rbp
	ret
	.size	div, .-div
	.globl	avg
	.type	avg, @function
avg:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 24
	mov	DWORD PTR -20[rbp], edi
	mov	DWORD PTR -24[rbp], esi
	mov	edx, DWORD PTR -20[rbp]
	mov	eax, DWORD PTR -24[rbp]
	add	eax, edx
	mov	DWORD PTR -4[rbp], eax
	mov	eax, DWORD PTR -4[rbp]
	mov	esi, 2
	mov	edi, eax
	call	div
	leave
	ret
	.size	avg, .-avg
	.section	.rodata
.LC0:
	.string	"%d+%d"
.LC1:
	.string	"average: %d"
	.text
	.globl	main
	.type	main, @function
main:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 16
	mov	DWORD PTR -8[rbp], 3
	mov	DWORD PTR -4[rbp], 4
	mov	DWORD PTR -12[rbp], 0
	jmp	.L6
.L7:
	mov	edx, DWORD PTR -8[rbp]
	mov	eax, DWORD PTR -12[rbp]
	mov	esi, eax
	lea	rdi, .LC0[rip]
	mov	eax, 0
	call	printf@PLT
	add	DWORD PTR -12[rbp], 1
.L6:
	cmp	DWORD PTR -12[rbp], 9
	jle	.L7
	mov	esi, 4
	mov	edi, 3
	call	avg
	mov	esi, eax
	lea	rdi, .LC1[rip]
	mov	eax, 0
	call	printf@PLT
	mov	eax, 0
	leave
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
