	/* mulx 4×4 SCHOOLBOOK.  rdx=multiplier (mulx reads from it).
	 * r10=a, r9=b, t[0..7] on stack at rsp.  adcx uses CF, adox uses
	 * OF — two independent carry chains let the mulx's pipeline freely
	 * (mulx doesn't touch flags at all).  ~11 cyc vs ~32 for mul+adc.
	 * Requires BMI2+ADX. */

	/* Row 0: a[0] × b[0..3] → t[0..4] */
	mov	rdx, [r10]
	mulx	r11, rax, [r9]      /* r11:rax = a[0]·b[0] */
	mov	[rsp], rax
	mulx	rcx, rax, [r9+8]
	add	r11, rax            /* hi0 + lo1 */
	mulx	rsi, rax, [r9+16]
	adc	rcx, rax
	mulx	rdi, rax, [r9+24]
	adc	rsi, rax
	adc	rdi, 0
	/* r11,rcx,rsi,rdi = partial t[1..4] */

	/* Row 1: a[1] × b[0..3] → t[1..5] */
	mov	rdx, [r10+8]
	xor	ebp, ebp            /* clear CF,OF */
	mulx	rbx, rax, [r9]
	adcx	r11, rax
	mov	[rsp+8], r11
	adox	rcx, rbx
	mulx	rbx, rax, [r9+8]
	adcx	rcx, rax
	adox	rsi, rbx
	mulx	rbx, rax, [r9+16]
	adcx	rsi, rax
	adox	rdi, rbx
	mulx	rbx, rax, [r9+24]
	adcx	rdi, rax
	adox	rbx, rbp            /* rbp=0, absorbs final OF */
	adcx	rbx, rbp            /* + final CF */
	/* rcx,rsi,rdi,rbx = partial t[2..5] */

	/* Row 2 */
	mov	rdx, [r10+16]
	xor	ebp, ebp
	mulx	r11, rax, [r9]
	adcx	rcx, rax
	mov	[rsp+16], rcx
	adox	rsi, r11
	mulx	r11, rax, [r9+8]
	adcx	rsi, rax
	adox	rdi, r11
	mulx	r11, rax, [r9+16]
	adcx	rdi, rax
	adox	rbx, r11
	mulx	r11, rax, [r9+24]
	adcx	rbx, rax
	adox	r11, rbp
	adcx	r11, rbp
	/* rsi,rdi,rbx,r11 = partial t[3..6] */

	/* Row 3 */
	mov	rdx, [r10+24]
	xor	ebp, ebp
	mulx	rcx, rax, [r9]
	adcx	rsi, rax
	mov	[rsp+24], rsi
	adox	rdi, rcx
	mulx	rcx, rax, [r9+8]
	adcx	rdi, rax
	mov	[rsp+32], rdi
	adox	rbx, rcx
	mulx	rcx, rax, [r9+16]
	adcx	rbx, rax
	mov	[rsp+40], rbx
	adox	r11, rcx
	mulx	rcx, rax, [r9+24]
	adcx	r11, rax
	mov	[rsp+48], r11
	adox	rcx, rbp
	adcx	rcx, rbp
	mov	[rsp+56], rcx
