# Basic secure erasure (recommended)
irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/refs/heads/main/code/Invoke-SecureEraser.ps1" | iex

# Maximum security with verification
irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/refs/heads/main/code/Invoke-SecureEraser.ps1" | iex -EncryptionRounds 7 -Verify -Force

# Silent automated mode
irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/refs/heads/main/code/Invoke-SecureEraser.ps1" | iex -Silent -EncryptionRounds 5
