	/* Carry-correction table: adjust[c+4] = c·C + (c<0 ? p : 0).
	 * S + adjust ∈ [0, 2p) guaranteed → one cond-sub finishes.
	 * 10 entries × 4 qwords = 320 B. */
	.align 32
carry_adjust_table:
	/* c=-4: */ .quad 0xfffffffffffffffb, 0x00000004ffffffff, 0x0000000000000000, 0xfffffffb00000005
	/* c=-3: */ .quad 0xfffffffffffffffc, 0x00000003ffffffff, 0x0000000000000000, 0xfffffffc00000004
	/* c=-2: */ .quad 0xfffffffffffffffd, 0x00000002ffffffff, 0x0000000000000000, 0xfffffffd00000003
	/* c=-1: */ .quad 0xfffffffffffffffe, 0x00000001ffffffff, 0x0000000000000000, 0xfffffffe00000002
	/* c=+0: */ .quad 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	/* c=+1: */ .quad 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe
	/* c=+2: */ .quad 0x0000000000000002, 0xfffffffe00000000, 0xffffffffffffffff, 0x00000001fffffffd
	/* c=+3: */ .quad 0x0000000000000003, 0xfffffffd00000000, 0xffffffffffffffff, 0x00000002fffffffc
	/* c=+4: */ .quad 0x0000000000000004, 0xfffffffc00000000, 0xffffffffffffffff, 0x00000003fffffffb
	/* c=+5: */ .quad 0x0000000000000005, 0xfffffffb00000000, 0xffffffffffffffff, 0x00000004fffffffa

	/* All 10 entries verified: 0 ≤ adj AND S+adj < 2p for all S < 2^256. */
