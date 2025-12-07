#!/data/data/com.termux/files/usr/bin/bash
# Termux:Boot script for LMSEC
# Place this in ~/.termux/boot/

# Mark this as a boot session so LMSEC doesn't block
export TERMUX_BOOT=1

# Acquire wakelock to prevent device sleep during boot
termux-wake-lock

# Wait for Termux to fully initialize
sleep 2

# Mark boot session (LMSEC will skip lock for 30 seconds)
python3 ~/LMSEC.py --boot-prepare 2>/dev/null

# Start your services here (they won't be blocked by LMSEC)
# Example:
# sshd
# node server.js &

# Optional: Lock terminals opened AFTER boot completes
# Wait 30 seconds, then lock will activate on new terminal sessions
# (Old marker expires automatically)

# Release wakelock
termux-wake-unlock
