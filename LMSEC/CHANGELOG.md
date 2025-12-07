# LMSEC Changelog

## v2.1.1 - Termux:Boot Compatibility Patch (2025-12-07)

### 🔧 Fixed
- **Boot blocking issue**: LMSEC no longer blocks Termux:Boot scripts
- Lock now auto-detects boot sessions and skips gracefully
- Services can now start properly on device boot

### ✨ Added
- `--boot-prepare` command for marking boot sessions
- `TERMUX_BOOT` environment variable detection
- `LMSEC_SKIP` environment variable to temporarily disable lock
- Boot session detection via process parent (ppid)
- Non-TTY session detection (skips background processes)
- Boot marker file with 30-second expiry
- Example Termux:Boot script (`termux-boot-example.sh`)

### 🎯 Usage
**For Termux:Boot integration:**
```bash
# In ~/.termux/boot/start-services.sh
export TERMUX_BOOT=1
python3 ~/LMSEC.py --boot-prepare
# Your services here - won't be blocked
```

**To temporarily skip lock:**
```bash
export LMSEC_SKIP=1
# Lock won't activate in this session
```

### 📝 Technical Details
- Boot detection checks:
  1. `TERMUX_BOOT` env var
  2. Boot marker file age (<30s)
  3. Parent process is init (ppid=1)
  4. stdin is not a TTY
- Silent skip in boot contexts (no blocking, no errors)
- Audit log still records boot skip events

---

## v2.1.0 - Fingerprint Authentication (2025-12-07)

### ✨ Added
- Android fingerprint authentication via Termux:API
- Automatic fallback to password on fingerprint failure
- 15-second fingerprint timeout with graceful degradation

### 🔒 Security
- PBKDF2-SHA256 with 200,000 iterations
- HMAC config integrity verification
- Watchdog daemon for process kill protection
- Monotonic time lockout (clock manipulation immune)

---

## v2.0.0 - Initial Release (2025-12-07)

First public release of LMSEC.
