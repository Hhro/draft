sub_140001000:
	sub	rsp, 0x28
	cmp	dword ptr [rip + 0xc5c65], 0
	jne	0x140032490
	add	rsp, 0x28
	ret	
sub_140001020:
	push	rdi
	sub	rsp, 0x20
	mov	rdi, rcx
	mov	rcx, qword ptr [rcx]
	test	rcx, rcx
	jne	0x140032f50
	xor	eax, eax
	mov	dword ptr [rdi + 0x10], eax
	add	rsp, 0x20
	pop	rdi
	ret	
	mov	qword ptr [rsp + 8], rbx
	push	rdi
	sub	rsp, 0x20
	mov	rcx, qword ptr [rdx]
	mov	rbx, r8
	mov	rdi, rdx
	test	rcx, rcx
	jne	0x14000106c
	xor	r11d, r11d
	mov	qword ptr [rdx], r11
	mov	byte ptr [r8], r11b
	mov	rbx, qword ptr [rsp + 0x30]
	add	rsp, 0x20
	pop	rdi
	ret	
	cmp	byte ptr [r8], 0
	je	0x140001058
	jmp	0x1400315e0
sub_140001080:
	mov	qword ptr [rsp + 8], rbx
	push	rdi
	sub	rsp, 0x20
	lea	rbx, [rip + 0xc5e07]
	lea	rdi, [rip + 0xc6e38]
	nop	dword ptr [rax + rax]
	mov	rcx, qword ptr [rbx]
	test	rcx, rcx
	jne	0x1400324d0
	add	rbx, 8
	cmp	rbx, rdi
	jl	0x1400010a0
	lea	r8, [rip + 0xc5db4]
	lea	rdx, [rip + 0xc5da5]
	lea	rcx, [rip + 0xc5aa6]
	call	0x140001040
	lea	r8, [rip + 0xc5db2]
	lea	rdx, [rip + 0xc5da3]
	lea	rcx, [rip + 0xc5a8c]
	call	0x140001040
	lea	rcx, [rip + 0xc5a80]
	mov	rbx, qword ptr [rsp + 0x30]
	add	rsp, 0x20
	pop	rdi
	jmp	0x140001000
sub_140001100:
	push	rbx
	sub	rsp, 0x20
	mov	rbx, rcx
	add	rcx, -0x110
	mov	rax, qword ptr [rcx]
	movsxd	rdx, dword ptr [rax + 4]
	lea	rax, [rip + 0xa0632]
	mov	qword ptr [rdx + rbx - 0x110], rax
	call	0x140014220
	lea	rcx, [rbx - 0xf0]
	call	0x1400011a0
	lea	rcx, [rbx - 0x108]
	add	rsp, 0x20
	pop	rbx
	jmp	0x140001020
sub_140001150:
	mov	qword ptr [rsp + 8], rbx
	push	rdi
	sub	rsp, 0x20
	mov	rbx, rcx
	mov	rcx, qword ptr [rcx + 0x48]
	test	rcx, rcx
	jne	0x140031700
	mov	rcx, qword ptr [rbx + 0x58]
	xor	edi, edi
	mov	qword ptr [rbx + 0x48], rdi
	test	rcx, rcx
	jne	0x14003170b
	mov	qword ptr [rbx + 0x58], rdi
	mov	dword ptr [rbx + 0x60], edi
	mov	dword ptr [rbx + 0x64], edi
	mov	dword ptr [rbx + 0x68], edi
	mov	byte ptr [rbx + 0x20], dil
	mov	rbx, qword ptr [rsp + 0x30]
	add	rsp, 0x20
	pop	rdi
	ret	
sub_1400011a0:
	push	rbx
	sub	rsp, 0x20
	mov	rbx, rcx
	add	rcx, 0xd0
	call	0x140002610
	lea	rcx, [rbx + 0x68]
	call	0x140001a60
	mov	rcx, rbx
	add	rsp, 0x20
	pop	rbx
	jmp	0x140001a60
sub_1400011d0:
	mov	qword ptr [rsp + 8], rbx
	push	rdi
	sub	rsp, 0x20
	cmp	byte ptr [rcx + 0x11], 0
	mov	rdi, rdx
	mov	rbx, rcx
	jne	0x140031390
	mov	ecx, 0x10
	call	0x140016ed8
	test	rax, rax
	je	0x1400313a5
	mov	ecx, dword ptr [rdi]
	mov	r11, rax
	mov	dword ptr [rax], ecx
	mov	rax, qword ptr [rbx + 8]
	mov	qword ptr [r11 + 8], rax
	inc	qword ptr [rbx]
	mov	qword ptr [rbx + 8], r11
	mov	rbx, qword ptr [rsp + 0x30]
	add	rsp, 0x20
	pop	rdi
	ret	
sub_140001220:
	push	rbx
	sub	rsp, 0x20
	mov	rbx, rcx
	mov	rcx, qword ptr [rcx]
	test	rcx, rcx
	je	0x140001236
	call	0x140016a60
	lea	rcx, [rbx + 0x188]
	call	0x140015720
	lea	rcx, [rbx + 0x148]
	call	0x140002610
	lea	rcx, [rbx + 0xd0]
	call	0x140001280
	lea	rcx, [rbx + 0x58]
	call	0x140001280
	lea	rcx, [rbx + 0x38]
	call	0x140002610
	lea	rcx, [rbx + 0x18]
	add	rsp, 0x20
	pop	rbx
	jmp	0x140002610
sub_140001280:
	push	rbx
	sub	rsp, 0x20
	mov	rbx, rcx
	call	0x140001150
	lea	rcx, [rbx + 0x28]
	call	0x140002610
	mov	rcx, rbx
	add	rsp, 0x20
	pop	rbx
	jmp	0x140002610
sub_1400012b0:
	push	rdi
	sub	rsp, 0x20
	cmp	qword ptr [rcx + 0x10], 0
	mov	rdi, rcx
	ja	0x1400012ce
	mov	qword ptr [rcx + 0x10], 0
	add	rsp, 0x20
	pop	rdi
	ret	
	mov	qword ptr [rsp + 0x30], rbx
	mov	qword ptr [rsp + 0x38], rsi
	xor	ebx, ebx
	mov	rax, qword ptr [rdi + 8]
	mov	rsi, qword ptr [rax + rbx*8]
	test	rsi, rsi
	je	0x1400012f7
	mov	rcx, rsi
	call	0x140002610
	mov	rcx, rsi
	call	0x140016a60
	inc	rbx
	cmp	rbx, qword ptr [rdi + 0x10]
	jb	0x1400012da
	mov	rsi, qword ptr [rsp + 0x38]
	mov	rbx, qword ptr [rsp + 0x30]
	mov	qword ptr [rdi + 0x10], 0
	add	rsp, 0x20
	pop	rdi
	ret	
sub_140001320:
	push	rbx
	sub	rsp, 0x20
	mov	rbx, rcx
	mov	rcx, qword ptr [rcx]
	test	rcx, rcx
	je	0x140001336
	call	0x140016a60
	lea	rcx, [rbx + 0x1c0]
	call	0x140001280
	lea	rcx, [rbx + 0x178]
	call	0x140002610
	lea	rcx, [rbx + 0x158]
	call	0x140002610
	lea	rcx, [rbx + 0x138]
	call	0x140002610
	lea	rcx, [rbx + 0x118]
	call	0x140002610
	lea	rcx, [rbx + 0x10]
	add	rsp, 0x20
	pop	rbx
	jmp	0x140013ea0
	mov	qword ptr [rsp + 8], rbx
	push	rdi
	sub	rsp, 0x230
	lea	rcx, [rip + 0xc6b5c]
	mov	ebx, r8d
	mov	rdi, rdx
	call	0x140004300
	test	al, al
	je	0x140034fb0
	lea	rcx, [rip + 0xc4dd2]
	call	0x140001460
	test	eax, eax
	jne	0x140034fb0
	lea	rcx, [rip + 0xc4dbe]
	call	0x140011b40
	test	eax, eax
	jne	0x140034fb0
	lea	r9, [rsp + 0x258]
	lea	r8, [rsp + 0x20]
	mov	edx, 0x104
	mov	rcx, rdi
	call	GetFullPathNameW
	lea	rdx, [rsp + 0x20]
	lea	rcx, [rip + 0xc4efa]
	call	0x1400107e0
	mov	rdx, qword ptr [rsp + 0x258]
	lea	rcx, [rip + 0xc4ec6]
	call	0x1400107e0
	mov	rax, qword ptr [rsp + 0x258]
	xor	r11d, r11d
	mov	word ptr [rax - 2], r11w
	cmp	word ptr [rsp + 0x24], r11w
	je	0x140034fba
	lea	rdx, [rsp + 0x20]
	lea	rcx, [rip + 0xc4ed9]
	call	0x1400107e0
	mov	dword ptr [rip + 0xc4e86], ebx
	xor	eax, eax
	mov	rbx, qword ptr [rsp + 0x240]
	add	rsp, 0x230
	pop	rdi
	ret	
sub_140001460:
	mov	rax, rsp
	mov	qword ptr [rax + 8], rbx
	push	rbp
	push	rsi
	push	rdi
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 0xe0
	xor	edx, edx
	xor	r9d, r9d
	xor	r14d, r14d
	mov	qword ptr [rsp + 0x78], rdx
	xor	r15d, r15d
	xor	r13d, r13d
	mov	edi, 1
	mov	dword ptr [rsp + 0x128], r9d
	mov	dword ptr [rsp + 0xd8], r9d
	mov	qword ptr [rax - 0x98], r14
	mov	byte ptr [rax - 0x90], dl
	mov	byte ptr [rax - 0x8f], dl
	mov	dword ptr [rsp + 0x130], edx
	mov	dword ptr [rsp + 0x138], edx
	mov	dword ptr [rsp + 0x44], edx
	mov	qword ptr [rsp + 0x60], rdx
	mov	qword ptr [rsp + 0x68], rdx
	mov	byte ptr [rsp + 0x70], dl
	mov	byte ptr [rsp + 0x71], dl
	mov	qword ptr [rax - 0x58], rdx
	mov	qword ptr [rax - 0x50], rdx
	mov	byte ptr [rax - 0x48], dl
	mov	byte ptr [rax - 0x47], dl
	mov	qword ptr [rsp + 0x48], rdx
	mov	qword ptr [rsp + 0x50], rdx
	mov	byte ptr [rsp + 0x58], dl
	mov	byte ptr [rsp + 0x59], dl
	mov	qword ptr [rax - 0x70], rdx
	mov	qword ptr [rax - 0x68], rdx
	mov	byte ptr [rax - 0x60], dl
	mov	byte ptr [rax - 0x5f], dl
	mov	qword ptr [rax - 0x88], rdx
	mov	qword ptr [rax - 0x80], rdx
	mov	byte ptr [rax - 0x78], dl
	mov	byte ptr [rax - 0x77], dl
	xor	r12d, r12d
	jmp	0x140001580
	mov	rax, qword ptr [r11 + 8]
	cmp	word ptr [rax + 8], 0x7f
	jne	0x140033942
	dec	r13d
	dec	r12d
	cmp	qword ptr [rsp + 0x78], rsi
	je	0x140033901
	cmp	byte ptr [rsp + 0x89], sil
	jne	0x14003390b
	mov	ebx, dword ptr [r14]
	lea	rcx, [rsp + 0x78]
	call	0x14000ff50
	mov	r14, qword ptr [rsp + 0x80]
	test	r13d, r13d
	js	0x140033a40
	cmp	r12d, ebx
	jne	0x140033a40
	mov	r9d, dword ptr [rsp + 0x128]
	mov	edx, dword ptr [rsp + 0x130]
	cmp	edi, dword ptr [rip + 0xc698a]
	jg	0x14000176e
	test	edi, edi
	jle	0x14000176e
	movsxd	rbx, edi
	shl	rbx, 5
	add	rbx, qword ptr [rip + 0xc69ce]
	test	rbx, rbx
	je	0x1400017cb
	inc	edi
	xor	ebp, ebp
	xor	esi, esi
	lea	eax, [rdi - 1]
	xor	r8d, r8d
	mov	dword ptr [rip + 0xc4d83], eax
	mov	r11, qword ptr [rbx + 8]
	mov	r10, qword ptr [r11]
	movzx	r9d, word ptr [r10 + 8]
	cmp	r9w, 0x7f
	je	0x1400015fb
	xor	edx, edx
	mov	rcx, r11
	nop	word ptr [rax + rax]
	mov	rax, qword ptr [rcx + 8]
	add	rcx, 8
	inc	edx
	inc	r8
	cmp	word ptr [rax + 8], 0x7f
	jne	0x1400015e0
	test	edx, edx
	je	0x1400015fb
	dec	r8
	mov	edx, dword ptr [rsp + 0x130]
	test	r9w, r9w
	mov	r9d, dword ptr [rsp + 0x128]
	jne	0x140001580
	mov	eax, dword ptr [r10]
	cmp	eax, 4
	je	0x1400016be
	cmp	eax, 0xd
	je	0x140001747
	cmp	eax, 0xe
	je	0x14000151c
	cmp	eax, 8
	je	0x140001775
	sub	eax, 5
	cmp	eax, 0x1c
	ja	0x140001580
	lea	rdx, [rip - 0x164e]
	cdqe	
	mov	ecx, dword ptr [rdx + rax*4 + 0x19ec]
	add	rcx, rdx
	jmp	rcx
	mov	rax, qword ptr [r11 + 8]
	cmp	word ptr [rax + 8], 0x7f
	jne	0x140033942
	sub	dword ptr [rsp + 0xd8], 1
	lea	rcx, [rip + 0xc4b06]
	jne	0x14003396d
	mov	eax, dword ptr [rsp + 0x44]
	mov	r8d, dword ptr [rsp + 0x138]
	mov	dword ptr [rsp + 0x38], r15d
	mov	dword ptr [rsp + 0x30], eax
	mov	eax, r9d
	mov	r9d, dword ptr [rsp + 0x130]
	mov	dword ptr [rsp + 0x28], eax
	mov	edx, r12d
	mov	dword ptr [rsp + 0x20], r13d
	call	0x140013710
	test	eax, eax
	je	0x140001571
	jmp	0x14003397b
	xor	eax, eax
	test	ax, ax
	je	0x1400016df
	mov	r10, qword ptr [r11 + rsi*8 + 8]
	inc	rsi
	inc	ebp
	mov	ax, word ptr [r10 + 8]
	cmp	ax, 0x7f
	jne	0x1400016c0
	jmp	0x140033a88
	cmp	dword ptr [r10], 5
	jne	0x1400016c5
	mov	rax, qword ptr [r11 + r8*8]
	cmp	word ptr [rax + 8], 0
	jne	0x140001712
	cmp	dword ptr [rax], 5
	jne	0x140001712
	mov	dword ptr [rsp + 0x40], r12d
	lea	rdx, [rsp + 0x40]
	lea	rcx, [rsp + 0xc0]
	inc	r15d
	inc	r12d
	call	0x1400011d0
	mov	rax, qword ptr [rbx + 8]
	mov	edx, dword ptr [rsp + 0x130]
	mov	r9d, dword ptr [rsp + 0x128]
	mov	rcx, qword ptr [rax + rsi*8 + 8]
	inc	ebp
	cmp	word ptr [rcx + 8], 0
	jne	0x140001580
	mov	eax, dword ptr [rcx]
	cmp	eax, 0x23
	je	0x140001580
	jmp	0x140033914
	mov	dword ptr [rsp + 0x40], r12d
	lea	rdx, [rsp + 0x40]
	lea	rcx, [rsp + 0x78]
	inc	r13d
	inc	r12d
	call	0x1400011d0
	mov	r14, qword ptr [rsp + 0x80]
	jmp	0x140001571
	xor	ebx, ebx
	jmp	0x1400015a2
	mov	rax, qword ptr [r11 + 8]
	cmp	word ptr [rax + 8], 0x7f
	jne	0x140033942
	dec	r15d
	dec	r12d
	cmp	qword ptr [rsp + 0xc0], rsi
	je	0x1400338f7
	lea	rcx, [rsp + 0xc0]
	call	0x140013800
	lea	rcx, [rsp + 0xc0]
	mov	ebx, dword ptr [rax]
	call	0x14000ff50
	test	r15d, r15d
	js	0x140033a2c
	cmp	r12d, ebx
	je	0x140001571
	jmp	0x140033a2c
	mov	eax, dword ptr [rsp + 0x44]
	mov	r8d, dword ptr [rsp + 0x138]
	mov	dword ptr [rsp + 0x38], r15d
	mov	dword ptr [rsp + 0x30], eax
	mov	dword ptr [rsp + 0x28], r9d
	mov	r9d, edx
	lea	rcx, [rip + 0xc4991]
	xor	edx, edx
	mov	dword ptr [rsp + 0x20], r13d
	call	0x140013710
	test	eax, eax
	jne	0x14003397b
	cmp	dword ptr [rsp + 0xd8], eax
	jne	0x140033958
	lea	rcx, [rsp + 0x90]
	call	0x140014090
	lea	rcx, [rsp + 0x78]
	call	0x140014090
	lea	rcx, [rsp + 0xa8]
	call	0x140014090
	lea	rcx, [rsp + 0x48]
	call	0x140014090
	lea	rcx, [rsp + 0xc0]
	call	0x140014090
	lea	rcx, [rsp + 0x60]
	call	0x140014090
	xor	eax, eax
	mov	rbx, qword ptr [rsp + 0x120]
	add	rsp, 0xe0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rdi
	pop	rsi
	pop	rbp
	ret	
	mov	eax, dword ptr [rsp + 0xd8]
	lea	rcx, [rip + 0xc4900]
	inc	eax
	cmp	eax, 1
	jg	0x14003396d
	mov	dword ptr [rsp + 0xd8], eax
	jmp	0x140001680
	mov	rax, qword ptr [r11 + 8]
	cmp	word ptr [rax + 8], 0x7f
	jne	0x140033942
	inc	dword ptr [rsp + 0x138]
	mov	dword ptr [rsp + 0x40], r12d
	lea	rdx, [rsp + 0x40]
	lea	rcx, [rsp + 0x90]
	inc	r12d
	call	0x1400011d0
	mov	r9d, dword ptr [rsp + 0x128]
	jmp	0x140001579
	mov	r9d, dword ptr [rsp + 0x130]
	mov	dword ptr [rsp + 0x40], r12d
	lea	rdx, [rsp + 0x40]
	inc	r9d
	lea	rcx, [rsp + 0xa8]
	inc	r12d
	mov	dword ptr [rsp + 0x130], r9d
	call	0x1400011d0
	mov	r9d, dword ptr [rsp + 0x128]
	jmp	0x140001579
	mov	esi, dword ptr [rsp + 0x138]
	lea	rcx, [rsp + 0x90]
	dec	r12d
	dec	esi
	mov	dword ptr [rsp + 0x138], esi
	call	0x1400161b0
	test	al, al
	jne	0x140033727
	lea	rcx, [rsp + 0x90]
	call	0x140013800
	lea	rcx, [rsp + 0x90]
	mov	ebx, dword ptr [rax]
	call	0x14000ff50
	test	esi, esi
	js	0x1400339ca
	cmp	r12d, ebx
	jne	0x1400339ca
	mov	r9d, dword ptr [rsp + 0x128]
	jmp	0x140001579
	mov	rax, qword ptr [r11 + 8]
	cmp	word ptr [rax + 8], 0x7f
	jne	0x140033942
	mov	r9d, dword ptr [rsp + 0x130]
	lea	rcx, [rsp + 0xa8]
	dec	r12d
	dec	r9d
	mov	dword ptr [rsp + 0x130], r9d
	call	0x1400161b0
	test	al, al
	jne	0x140033731
	lea	rcx, [rsp + 0xa8]
	call	0x140013800
	lea	rcx, [rsp + 0xa8]
	mov	ebx, dword ptr [rax]
	call	0x14000ff50
	mov	edx, dword ptr [rsp + 0x130]
	test	edx, edx
	js	0x1400339dc
	cmp	r12d, ebx
	jne	0x1400339dc
	mov	r9d, dword ptr [rsp + 0x128]
	jmp	0x140001580
	nop	
