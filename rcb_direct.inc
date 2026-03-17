	/* ================================================================
	 * RCB DIRECT — straight-line 43-op sequence, no bytecode dispatch.
	 * Same EFD-rescheduled schedule as bc_rcb, but each op is a direct
	 * call with explicit slot addressing.  Saves ~12 cyc/op decoder
	 * overhead × 43 ops × 384 dispatches ≈ 198K cyc.
	 * ================================================================ */
rcb_direct:
	push	rbp
	push	rbx                 /* fe_mul_m clobbers */
	/*  1: slot3 = slot0 mul slot5 */
	lea	rdi, [r14+96]
	mov	rsi, r14
	lea	rdx, [r14+160]
	mov	rcx, r8
	call	fe_mul_m
	/*  2: slot4 = slot1 mul slot6 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+32]
	lea	rdx, [r14+192]
	mov	rcx, r8
	call	fe_mul_m
	/*  3: slot9 = slot2 mul slot7 */
	lea	rdi, [r14+288]
	lea	rsi, [r14+64]
	lea	rdx, [r14+224]
	mov	rcx, r8
	call	fe_mul_m
	/*  4: slot11 = slot0 add slot1 */
	lea	rdi, [r14+352]
	mov	rsi, r14
	lea	rdx, [r14+32]
	call	Fadd
	/*  5: slot15 = slot5 add slot6 */
	lea	rdi, [r14+480]
	lea	rsi, [r14+160]
	lea	rdx, [r14+192]
	call	Fadd
	/*  6: slot11 = slot11 mul slot15 */
	lea	rdi, [r14+352]
	lea	rsi, [r14+352]
	lea	rdx, [r14+480]
	mov	rcx, r8
	call	fe_mul_m
	/*  7: slot15 = slot3 add slot4 */
	lea	rdi, [r14+480]
	lea	rsi, [r14+96]
	lea	rdx, [r14+128]
	call	Fadd
	/*  8: slot11 = slot11 sub slot15 */
	lea	rdi, [r14+352]
	lea	rsi, [r14+352]
	lea	rdx, [r14+480]
	call	.Lop3_fast
	/*  9: slot15 = slot1 add slot2 */
	lea	rdi, [r14+480]
	lea	rsi, [r14+32]
	lea	rdx, [r14+64]
	call	Fadd
	/* 10: slot0 = slot2 add slot0 */
	mov	rdi, r14
	lea	rsi, [r14+64]
	mov	rdx, r14
	call	Fadd
	/* 11: slot1 = slot5 add slot7 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+160]
	lea	rdx, [r14+224]
	call	Fadd
	/* 12: slot2 = slot6 add slot7 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+192]
	lea	rdx, [r14+224]
	call	Fadd
	/* 13: slot15 = slot15 mul slot2 */
	lea	rdi, [r14+480]
	lea	rsi, [r14+480]
	lea	rdx, [r14+64]
	mov	rcx, r8
	call	fe_mul_m
	/* 14: slot2 = slot4 add slot9 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+128]
	lea	rdx, [r14+288]
	call	Fadd
	/* 15: slot15 = slot15 sub slot2 */
	lea	rdi, [r14+480]
	lea	rsi, [r14+480]
	lea	rdx, [r14+64]
	call	.Lop3_fast
	/* 16: slot0 = slot0 mul slot1 */
	mov	rdi, r14
	mov	rsi, r14
	lea	rdx, [r14+32]
	mov	rcx, r8
	call	fe_mul_m
	/* 17: slot1 = slot3 add slot9 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+96]
	lea	rdx, [r14+288]
	call	Fadd
	/* 18: slot1 = slot0 sub slot1 */
	lea	rdi, [r14+32]
	mov	rsi, r14
	lea	rdx, [r14+32]
	call	.Lop3_fast
	/* 19: slot2 = slot9 mul slot10 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+288]
	lea	rdx, [r14+320]
	mov	rcx, r8
	call	fe_mul_m
	/* 20: slot0 = slot1 sub slot2 */
	mov	rdi, r14
	lea	rsi, [r14+32]
	lea	rdx, [r14+64]
	call	.Lop3_fast
	/* 21: slot2 = slot0 add slot0 */
	lea	rdi, [r14+64]
	mov	rsi, r14
	mov	rdx, r14
	call	Fadd
	/* 22: slot0 = slot2 add slot0 */
	mov	rdi, r14
	lea	rsi, [r14+64]
	mov	rdx, r14
	call	Fadd
	/* 23: slot2 = slot4 sub slot0 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+128]
	mov	rdx, r14
	call	.Lop3_fast
	/* 24: slot0 = slot4 add slot0 */
	mov	rdi, r14
	lea	rsi, [r14+128]
	mov	rdx, r14
	call	Fadd
	/* 25: slot1 = slot1 mul slot10 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+32]
	lea	rdx, [r14+320]
	mov	rcx, r8
	call	fe_mul_m
	/* 26: slot4 = slot9 add slot9 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+288]
	lea	rdx, [r14+288]
	call	Fadd
	/* 27: slot9 = slot4 add slot9 */
	lea	rdi, [r14+288]
	lea	rsi, [r14+128]
	lea	rdx, [r14+288]
	call	Fadd
	/* 28: slot1 = slot1 sub slot9 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+32]
	lea	rdx, [r14+288]
	call	.Lop3_fast
	/* 29: slot1 = slot1 sub slot3 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+32]
	lea	rdx, [r14+96]
	call	.Lop3_fast
	/* 30: slot4 = slot1 add slot1 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+32]
	lea	rdx, [r14+32]
	call	Fadd
	/* 31: slot1 = slot4 add slot1 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+128]
	lea	rdx, [r14+32]
	call	Fadd
	/* 32: slot4 = slot3 add slot3 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+96]
	lea	rdx, [r14+96]
	call	Fadd
	/* 33: slot3 = slot4 add slot3 */
	lea	rdi, [r14+96]
	lea	rsi, [r14+128]
	lea	rdx, [r14+96]
	call	Fadd
	/* 34: slot3 = slot3 sub slot9 */
	lea	rdi, [r14+96]
	lea	rsi, [r14+96]
	lea	rdx, [r14+288]
	call	.Lop3_fast
	/* 35: slot4 = slot15 mul slot1 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+480]
	lea	rdx, [r14+32]
	mov	rcx, r8
	call	fe_mul_m
	/* 36: slot9 = slot3 mul slot1 */
	lea	rdi, [r14+288]
	lea	rsi, [r14+96]
	lea	rdx, [r14+32]
	mov	rcx, r8
	call	fe_mul_m
	/* 37: slot1 = slot0 mul slot2 */
	lea	rdi, [r14+32]
	mov	rsi, r14
	lea	rdx, [r14+64]
	mov	rcx, r8
	call	fe_mul_m
	/* 38: slot1 = slot9 add slot1 */
	lea	rdi, [r14+32]
	lea	rsi, [r14+288]
	lea	rdx, [r14+32]
	call	Fadd
	/* 39: slot0 = slot0 mul slot11 */
	mov	rdi, r14
	mov	rsi, r14
	lea	rdx, [r14+352]
	mov	rcx, r8
	call	fe_mul_m
	/* 40: slot0 = slot0 sub slot4 */
	mov	rdi, r14
	mov	rsi, r14
	lea	rdx, [r14+128]
	call	.Lop3_fast
	/* 41: slot2 = slot15 mul slot2 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+480]
	lea	rdx, [r14+64]
	mov	rcx, r8
	call	fe_mul_m
	/* 42: slot4 = slot11 mul slot3 */
	lea	rdi, [r14+128]
	lea	rsi, [r14+352]
	lea	rdx, [r14+96]
	mov	rcx, r8
	call	fe_mul_m
	/* 43: slot2 = slot4 add slot2 */
	lea	rdi, [r14+64]
	lea	rsi, [r14+128]
	lea	rdx, [r14+64]
	call	Fadd
	pop	rbx
	pop	rbp
	ret
