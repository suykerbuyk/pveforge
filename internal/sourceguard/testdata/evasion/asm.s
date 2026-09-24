// Assembly writes another package's symbol with no directive at all.
TEXT ·poke(SB),4,$0-0
	MOVQ $10, github·com∕suykerbuyk∕pveforge∕internal∕roster·scryptWorkFactorOverride(SB)
	RET
