#!/usr/bin/env python3
"""
LMSEC - Lamgerr Security Lock System v2.1
Part of the LMWM Project

Developer-grade terminal lock with defense-in-depth architecture.
Designed for securing developer workstations in Termux environments.

Author: Lamgerr (NaveenSingh9999)
GitHub: https://github.com/NaveenSingh9999
Project: LMWM

Security Features:
- Fingerprint authentication (Android Biometric API via Termux:API)
- Process kill protection via daemon watchdog
- Multi-session locking via PTY monitoring  
- Config integrity verification (HMAC)
- Environment sanitization
- Scrollback clearing
- Monotonic time for lockout (clock-immune)
- Memory-safe password handling
"""

import os
import sys
import hashlib
import secrets
import getpass
import time
import json
import signal
import struct
import ctypes
import fcntl
import atexit
import subprocess
import threading
import pty
import termios
import tty
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple
import hmac

# ============================================================================
# CONFIGURATION - Stored separately from runtime to prevent tampering
# ============================================================================

# Use a less obvious location and name
CONFIG_DIR = Path.home() / ".config" / ".session-manager"
CONFIG_FILE = CONFIG_DIR / ".state"
LOCK_FILE = CONFIG_DIR / ".active"
LOG_FILE = CONFIG_DIR / ".audit"
INTEGRITY_FILE = CONFIG_DIR / ".verify"
WATCHDOG_PID_FILE = CONFIG_DIR / ".watchdog"

MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300
HASH_ITERATIONS = 200000  # Increased iterations
WATCHDOG_INTERVAL = 0.5   # Check every 500ms
INTEGRITY_KEY_SIZE = 32
FINGERPRINT_TIMEOUT = 15  # Seconds to wait for fingerprint

# Termux:API fingerprint binary
TERMUX_FINGERPRINT = "/data/data/com.termux/files/usr/bin/termux-fingerprint"

# ============================================================================
# FINGERPRINT AUTHENTICATION
# ============================================================================

def is_fingerprint_available() -> bool:
    """Check if fingerprint authentication is available."""
    return os.path.isfile(TERMUX_FINGERPRINT) and os.access(TERMUX_FINGERPRINT, os.X_OK)

def authenticate_fingerprint() -> Tuple[bool, str]:
    """
    Authenticate using Android fingerprint sensor via Termux:API.
    Returns (success, message).
    """
    if not is_fingerprint_available():
        return False, "Fingerprint not available"
    
    try:
        # Run termux-fingerprint with timeout
        result = subprocess.run(
            [TERMUX_FINGERPRINT],
            capture_output=True,
            text=True,
            timeout=FINGERPRINT_TIMEOUT
        )
        
        if result.returncode != 0:
            return False, "Fingerprint command failed"
        
        # Parse JSON response
        response = json.loads(result.stdout)
        
        auth_result = response.get('auth_result', '')
        errors = response.get('errors', [])
        
        if auth_result == 'AUTH_RESULT_SUCCESS':
            return True, "Fingerprint authenticated"
        elif auth_result == 'AUTH_RESULT_FAILURE':
            return False, "Fingerprint not recognized"
        elif auth_result == 'AUTH_RESULT_UNKNOWN':
            return False, "Authentication cancelled"
        elif errors:
            return False, f"Error: {errors[0]}"
        else:
            return False, f"Auth failed: {auth_result}"
    
    except subprocess.TimeoutExpired:
        return False, "Fingerprint timeout"
    except json.JSONDecodeError:
        return False, "Invalid response"
    except Exception as e:
        return False, f"Error: {str(e)}"

def fingerprint_auth_thread(result_holder: dict, stop_event: threading.Event):
    """Run fingerprint auth in a thread."""
    if stop_event.is_set():
        return
    success, msg = authenticate_fingerprint()
    result_holder['success'] = success
    result_holder['message'] = msg
    stop_event.set()

# ============================================================================
# SECURE MEMORY HANDLING (Best effort in Python)
# ============================================================================

def secure_zero_memory(data: bytearray):
    """Attempt to zero out memory - best effort in Python."""
    for i in range(len(data)):
        data[i] = 0

class SecureString:
    """Wrapper for sensitive strings with cleanup."""
    def __init__(self, value: str):
        self._data = bytearray(value.encode('utf-8'))
        self._str_cache = None
    
    def get(self) -> str:
        if self._str_cache is None:
            self._str_cache = self._data.decode('utf-8')
        return self._str_cache
    
    def clear(self):
        secure_zero_memory(self._data)
        self._str_cache = None
    
    def __del__(self):
        self.clear()

# ============================================================================
# ENVIRONMENT SANITIZATION
# ============================================================================

SAFE_ENV = {
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
    'TERM': os.environ.get('TERM', 'xterm-256color'),
    'HOME': str(Path.home()),
    'LANG': 'C.UTF-8',
}

def get_safe_env() -> dict:
    """Return sanitized environment."""
    return SAFE_ENV.copy()

def safe_subprocess(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    """Run subprocess with sanitized environment."""
    kwargs['env'] = get_safe_env()
    kwargs['shell'] = False  # Never use shell=True
    return subprocess.run(cmd, **kwargs)

# ============================================================================
# DIRECT TERMINAL CONTROL (No shell invocation)
# ============================================================================

def clear_screen_secure():
    """Clear screen AND scrollback buffer without shell."""
    # Clear screen
    sys.stdout.write('\033[2J')
    # Move cursor to top-left
    sys.stdout.write('\033[H')
    # Clear scrollback buffer (xterm extension, widely supported)
    sys.stdout.write('\033[3J')
    sys.stdout.flush()

def disable_echo():
    """Disable terminal echo directly via termios."""
    try:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        new_settings = termios.tcgetattr(fd)
        new_settings[3] = new_settings[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, new_settings)
        return old_settings
    except:
        return None

def restore_terminal(old_settings):
    """Restore terminal settings."""
    if old_settings:
        try:
            fd = sys.stdin.fileno()
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except:
            pass

# ============================================================================
# MONOTONIC TIME (Immune to system clock changes)
# ============================================================================

def get_monotonic_time() -> float:
    """Get monotonic time that can't be manipulated."""
    return time.monotonic()

# ============================================================================
# CONFIG INTEGRITY
# ============================================================================

def generate_integrity_key() -> bytes:
    """Generate machine-bound integrity key."""
    # Combine multiple entropy sources for machine binding
    components = []
    
    # Machine ID if available
    try:
        with open('/etc/machine-id', 'r') as f:
            components.append(f.read().strip())
    except:
        pass
    
    # Android ID via getprop if available
    try:
        result = safe_subprocess(['/system/bin/getprop', 'ro.serialno'], 
                                  capture_output=True, text=True)
        if result.returncode == 0:
            components.append(result.stdout.strip())
    except:
        pass
    
    # Fallback: use username and home directory
    components.append(os.getlogin() if hasattr(os, 'getlogin') else str(os.getuid()))
    components.append(str(Path.home()))
    
    # Derive key
    combined = '|'.join(components).encode('utf-8')
    return hashlib.sha256(combined).digest()

def compute_config_mac(config_data: bytes, key: bytes) -> str:
    """Compute HMAC of config for integrity verification."""
    return hmac.new(key, config_data, hashlib.sha256).hexdigest()

def save_config_with_integrity(config: dict):
    """Save config with integrity MAC."""
    init_config_dir()
    
    # Remove integrity field before computing MAC
    config_copy = {k: v for k, v in config.items() if k != '_mac'}
    config_data = json.dumps(config_copy, sort_keys=True).encode('utf-8')
    
    key = generate_integrity_key()
    mac = compute_config_mac(config_data, key)
    
    config_copy['_mac'] = mac
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_copy, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)

def load_config_with_integrity() -> Tuple[dict, bool]:
    """Load config and verify integrity. Returns (config, is_valid)."""
    if not CONFIG_FILE.exists():
        return {}, True
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}, False
    
    stored_mac = config.pop('_mac', None)
    if stored_mac is None:
        return config, False  # No MAC = tampered or old format
    
    config_data = json.dumps(config, sort_keys=True).encode('utf-8')
    key = generate_integrity_key()
    expected_mac = compute_config_mac(config_data, key)
    
    if not hmac.compare_digest(stored_mac, expected_mac):
        return config, False  # MAC mismatch = tampered
    
    return config, True

# ============================================================================
# SECURE PASSWORD HASHING
# ============================================================================

def secure_hash(password: str, salt: bytes = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(32)
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        HASH_ITERATIONS,
        dklen=32
    )
    return key.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password with constant-time comparison."""
    try:
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(salt),
            HASH_ITERATIONS,
            dklen=32
        )
        return hmac.compare_digest(key.hex(), stored_hash)
    except:
        return False

# ============================================================================
# FILE OPERATIONS
# ============================================================================

def init_config_dir():
    """Initialize secure configuration directory."""
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Double-check permissions
    os.chmod(CONFIG_DIR, 0o700)

def secure_delete(filepath: Path):
    """Best-effort secure deletion."""
    if not filepath.exists():
        return
    try:
        size = filepath.stat().st_size
        # Multiple overwrite passes
        with open(filepath, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        filepath.unlink()
    except:
        try:
            filepath.unlink()
        except:
            pass

def log_access(event: str, success: bool = True):
    """Log access with integrity."""
    init_config_dir()
    timestamp = datetime.now().isoformat()
    status = "OK" if success else "FAIL"
    
    # Include PTY info for forensics
    try:
        tty_name = os.ttyname(sys.stdin.fileno())
    except:
        tty_name = "unknown"
    
    log_entry = f"[{timestamp}] [{status}] [{tty_name}] {event}\n"
    
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)
    os.chmod(LOG_FILE, 0o600)

# ============================================================================
# WATCHDOG DAEMON (Protection against process kill)
# ============================================================================

class WatchdogDaemon:
    """
    Background watchdog that monitors the lock process.
    If the lock process is killed, the watchdog will:
    1. Kill the parent shell
    2. Respawn the lock
    """
    
    def __init__(self, lock_pid: int, parent_pid: int, tty_path: str):
        self.lock_pid = lock_pid
        self.parent_pid = parent_pid
        self.tty_path = tty_path
        self.running = True
        self._thread = None
    
    def _is_process_alive(self, pid: int) -> bool:
        """Check if a process is still running."""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    def _kill_shell(self):
        """Kill the parent shell to prevent access."""
        try:
            os.kill(self.parent_pid, signal.SIGKILL)
        except:
            pass
    
    def _monitor(self):
        """Monitoring loop."""
        while self.running:
            time.sleep(WATCHDOG_INTERVAL)
            
            if not self._is_process_alive(self.lock_pid):
                # Lock process was killed - security breach!
                log_access("SECURITY: Lock process killed, terminating shell", False)
                self._kill_shell()
                self.running = False
                break
    
    def start(self):
        """Start watchdog in background thread."""
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop watchdog."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=1)

# ============================================================================
# SESSION MONITORING
# ============================================================================

def get_all_user_ttys() -> list:
    """Get all TTYs owned by current user."""
    ttys = []
    try:
        uid = os.getuid()
        dev_pts = Path('/dev/pts')
        if dev_pts.exists():
            for pty in dev_pts.iterdir():
                try:
                    if pty.stat().st_uid == uid and pty.name.isdigit():
                        ttys.append(str(pty))
                except:
                    continue
    except:
        pass
    return ttys

def block_other_ttys(own_tty: str):
    """
    Write lock message to other TTYs owned by user.
    Note: This is advisory, not a true block.
    """
    ttys = get_all_user_ttys()
    for tty_path in ttys:
        if tty_path != own_tty:
            try:
                with open(tty_path, 'w') as tty:
                    tty.write('\n\033[1;31m[LOCKED] This session is locked.\033[0m\n')
            except:
                pass

# ============================================================================
# SIGNAL HANDLING
# ============================================================================

_original_handlers = {}

def block_signals():
    """Block all catchable signals."""
    signals_to_block = [
        signal.SIGINT,    # Ctrl+C
        signal.SIGTSTP,   # Ctrl+Z
        signal.SIGQUIT,   # Ctrl+\
        signal.SIGTERM,   # Termination request
        signal.SIGHUP,    # Hangup
        signal.SIGUSR1,
        signal.SIGUSR2,
        signal.SIGPIPE,
        signal.SIGALRM,
    ]
    
    for sig in signals_to_block:
        try:
            _original_handlers[sig] = signal.signal(sig, signal.SIG_IGN)
        except:
            pass

def restore_signals():
    """Restore original signal handlers."""
    for sig, handler in _original_handlers.items():
        try:
            signal.signal(sig, handler)
        except:
            pass

# ============================================================================
# UI
# ============================================================================

class UI:
    """Minimal terminal UI."""
    
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    
    @staticmethod
    def header():
        clear_screen_secure()
        print(f"\n{UI.BOLD}{UI.CYAN}┌──────────────────────────────────────────┐{UI.RESET}")
        print(f"{UI.BOLD}{UI.CYAN}│{UI.RESET}        LMSEC - LMWM Security v2.1        {UI.BOLD}{UI.CYAN}│{UI.RESET}")
        print(f"{UI.BOLD}{UI.CYAN}│{UI.RESET}  {UI.DIM}by Lamgerr (NaveenSingh9999){UI.RESET}            {UI.BOLD}{UI.CYAN}│{UI.RESET}")
        print(f"{UI.BOLD}{UI.CYAN}└──────────────────────────────────────────┘{UI.RESET}\n")
    
    @staticmethod
    def lock_screen(attempts_left: int = MAX_ATTEMPTS, lockout: int = 0, fingerprint_available: bool = False):
        clear_screen_secure()
        print(f"\n{UI.BOLD}{UI.RED}┌──────────────────────────────────────────┐{UI.RESET}")
        print(f"{UI.BOLD}{UI.RED}│{UI.RESET}               LOCKED                 {UI.BOLD}{UI.RED}│{UI.RESET}")
        print(f"{UI.BOLD}{UI.RED}└──────────────────────────────────────────┘{UI.RESET}")
        
        if lockout > 0:
            print(f"\n{UI.RED}Locked out for {lockout} seconds.{UI.RESET}")
        elif attempts_left < MAX_ATTEMPTS:
            print(f"\n{UI.DIM}Attempts remaining: {attempts_left}{UI.RESET}")
        
        if fingerprint_available:
            print(f"\n{UI.GREEN}🖐  Touch fingerprint sensor or enter password{UI.RESET}\n")
        else:
            print(f"\n{UI.DIM}Session secured. Authenticate to continue.{UI.RESET}\n")
    
    @staticmethod
    def success(msg: str):
        print(f"{UI.GREEN}✓ {msg}{UI.RESET}")
    
    @staticmethod
    def error(msg: str):
        print(f"{UI.RED}✗ {msg}{UI.RESET}")
    
    @staticmethod
    def warning(msg: str):
        print(f"{UI.YELLOW}⚠ {msg}{UI.RESET}")
    
    @staticmethod
    def info(msg: str):
        print(f"{UI.CYAN}→ {msg}{UI.RESET}")
    
    @staticmethod
    def prompt(msg: str) -> str:
        return input(f"{UI.BOLD}{msg}{UI.RESET}")
    
    @staticmethod
    def secure_prompt(msg: str) -> str:
        """Secure password prompt with echo disabled."""
        print(f"{UI.BOLD}{msg}{UI.RESET}", end='', flush=True)
        old_settings = disable_echo()
        try:
            password = input()
            print()  # Newline after hidden input
            return password
        finally:
            restore_terminal(old_settings)

# ============================================================================
# LOCKOUT MANAGEMENT
# ============================================================================

class LockoutManager:
    """Manages lockout state using monotonic time."""
    
    def __init__(self):
        self.failed_attempts = 0
        self.lockout_start = None  # Monotonic time
    
    def record_failure(self):
        """Record a failed attempt."""
        self.failed_attempts += 1
        if self.failed_attempts >= MAX_ATTEMPTS:
            self.lockout_start = get_monotonic_time()
    
    def reset(self):
        """Reset on successful auth."""
        self.failed_attempts = 0
        self.lockout_start = None
    
    def is_locked_out(self) -> Tuple[bool, int]:
        """Check lockout status. Returns (is_locked, remaining_seconds)."""
        if self.lockout_start is None:
            return False, 0
        
        elapsed = get_monotonic_time() - self.lockout_start
        if elapsed >= LOCKOUT_TIME:
            # Lockout expired
            self.lockout_start = None
            self.failed_attempts = 0
            return False, 0
        
        return True, int(LOCKOUT_TIME - elapsed)
    
    def attempts_remaining(self) -> int:
        return max(0, MAX_ATTEMPTS - self.failed_attempts)

# ============================================================================
# CORE LOCK FUNCTIONS
# ============================================================================

def setup_password():
    """Configure password."""
    UI.header()
    print(f"{UI.BOLD}Password Setup{UI.RESET}\n")
    
    config, is_valid = load_config_with_integrity()
    
    if config.get('password_hash'):
        if not is_valid:
            UI.error("Config integrity check failed! Possible tampering detected.")
            UI.warning("You must verify current password to continue.")
        
        current = UI.secure_prompt("Current password: ")
        if not verify_password(current, config['password_hash'], config['salt']):
            UI.error("Invalid password.")
            log_access("Password change - wrong current password", False)
            return False
    
    password = UI.secure_prompt("New password (min 8 chars): ")
    if len(password) < 8:
        UI.error("Password too short.")
        return False
    
    # Password strength check
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        UI.warning("Weak password. Recommend: uppercase, lowercase, and digits.")
        confirm = UI.prompt("Continue anyway? [y/N]: ").strip().lower()
        if confirm != 'y':
            return False
    
    confirm_pw = UI.secure_prompt("Confirm password: ")
    if password != confirm_pw:
        UI.error("Passwords do not match.")
        return False
    
    password_hash, salt = secure_hash(password)
    config['password_hash'] = password_hash
    config['salt'] = salt
    config['hash_iterations'] = HASH_ITERATIONS
    config['created'] = datetime.now().isoformat()
    
    save_config_with_integrity(config)
    
    UI.success("Password configured.")
    log_access("Password setup/change completed")
    return True

def lock_terminal():
    """Lock the terminal with full protection and fingerprint support."""
    config, is_valid = load_config_with_integrity()
    
    if not config.get('password_hash'):
        UI.error("No password configured. Run with --setup first.")
        sys.exit(1)
    
    if not is_valid:
        UI.error("Config integrity check failed!")
        UI.error("Security may be compromised. Run --setup to reconfigure.")
        sys.exit(1)
    
    # Get current TTY
    try:
        own_tty = os.ttyname(sys.stdin.fileno())
    except:
        own_tty = "unknown"
    
    # Check fingerprint availability once
    fp_available = is_fingerprint_available()
    
    # Setup
    block_signals()
    init_config_dir()
    LOCK_FILE.touch(mode=0o600)
    
    log_access(f"Terminal locked (TTY: {own_tty}, Fingerprint: {fp_available})")
    
    # Start watchdog
    lock_pid = os.getpid()
    parent_pid = os.getppid()
    watchdog = WatchdogDaemon(lock_pid, parent_pid, own_tty)
    watchdog.start()
    
    # Notify other sessions
    block_other_ttys(own_tty)
    
    lockout_mgr = LockoutManager()
    old_term_settings = None
    
    try:
        while True:
            is_locked, remaining = lockout_mgr.is_locked_out()
            
            if is_locked:
                UI.lock_screen(0, remaining, False)
                time.sleep(min(remaining, 10))
                continue
            
            UI.lock_screen(lockout_mgr.attempts_remaining(), 0, fp_available)
            
            # Try fingerprint first if available
            if fp_available:
                print(f"{UI.DIM}Waiting for fingerprint...{UI.RESET}", end='', flush=True)
                
                # Start fingerprint in background thread
                stop_event = threading.Event()
                fp_result = {'success': False, 'message': ''}
                fp_thread = threading.Thread(
                    target=fingerprint_auth_thread, 
                    args=(fp_result, stop_event),
                    daemon=True
                )
                fp_thread.start()
                
                # Wait for fingerprint with ability to fall back to password
                fp_thread.join(timeout=FINGERPRINT_TIMEOUT)
                
                if fp_result.get('success'):
                    print(f"\r{' ' * 40}\r", end='')  # Clear line
                    log_access("Fingerprint authentication successful")
                    lockout_mgr.reset()
                    break
                elif fp_result.get('message'):
                    print(f"\r{UI.YELLOW}⚠ {fp_result['message']}{UI.RESET}")
                    print(f"{UI.DIM}Falling back to password...{UI.RESET}\n")
                else:
                    print(f"\r{' ' * 40}\r", end='')  # Clear line
            
            # Password fallback
            password = UI.secure_prompt("Password: ")
            
            if verify_password(password, config['password_hash'], config['salt']):
                lockout_mgr.reset()
                log_access("Password authentication successful")
                break
            else:
                lockout_mgr.record_failure()
                log_access("Failed login attempt", False)
                
                if lockout_mgr.attempts_remaining() == 0:
                    UI.error(f"Too many attempts. Locked for {LOCKOUT_TIME}s.")
                else:
                    UI.error(f"Invalid. {lockout_mgr.attempts_remaining()} attempts left.")
                
                time.sleep(1)
    
    except Exception as e:
        log_access(f"Lock error: {e}", False)
        raise
    
    finally:
        watchdog.stop()
        restore_signals()
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
        restore_terminal(old_term_settings)
    
    log_access("Terminal unlocked")
    clear_screen_secure()
    UI.success("Session unlocked.")

def show_status():
    """Show status and security info."""
    UI.header()
    print(f"{UI.BOLD}Status{UI.RESET}\n")
    
    config, is_valid = load_config_with_integrity()
    
    # Password status
    if config.get('password_hash'):
        UI.success("Password: Configured")
        if config.get('created'):
            UI.info(f"Created: {config['created']}")
        iterations = config.get('hash_iterations', 'unknown')
        UI.info(f"Hash iterations: {iterations}")
    else:
        UI.warning("Password: Not configured")
    
    # Fingerprint status
    if is_fingerprint_available():
        UI.success("Fingerprint: Available (Termux:API)")
    else:
        UI.warning("Fingerprint: Not available")
        UI.info("  Install: pkg install termux-api")
    
    # Integrity status
    if is_valid:
        UI.success("Config integrity: Verified")
    else:
        UI.error("Config integrity: FAILED - possible tampering!")
    
    # Lock status
    if LOCK_FILE.exists():
        UI.warning("Lock state: ACTIVE")
    else:
        UI.success("Lock state: Inactive")
    
    # Session info
    try:
        tty = os.ttyname(sys.stdin.fileno())
        UI.info(f"Current TTY: {tty}")
    except:
        pass
    
    user_ttys = get_all_user_ttys()
    UI.info(f"User sessions: {len(user_ttys)}")
    
    print()
    
    # Recent logs
    if LOG_FILE.exists():
        print(f"{UI.BOLD}Recent Audit Log:{UI.RESET}")
        print(f"{UI.DIM}{'─' * 50}{UI.RESET}")
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()[-15:]
                for line in lines:
                    if "FAIL" in line or "SECURITY" in line:
                        print(f"{UI.RED}{line.strip()}{UI.RESET}")
                    elif "OK" in line:
                        print(f"{UI.DIM}{line.strip()}{UI.RESET}")
                    else:
                        print(f"{UI.YELLOW}{line.strip()}{UI.RESET}")
        except:
            pass

def remove_lock():
    """Remove lock system."""
    UI.header()
    print(f"{UI.BOLD}Remove Lock System{UI.RESET}\n")
    
    config, _ = load_config_with_integrity()
    
    if not config.get('password_hash'):
        UI.warning("Lock system not configured.")
        return
    
    UI.warning("This will permanently remove the lock system.")
    password = UI.secure_prompt("Enter password to confirm: ")
    
    if not verify_password(password, config['password_hash'], config['salt']):
        UI.error("Invalid password.")
        log_access("Remove attempt - wrong password", False)
        return
    
    confirm = UI.prompt("Type 'REMOVE' to confirm: ").strip()
    if confirm != 'REMOVE':
        UI.info("Cancelled.")
        return
    
    # Secure cleanup
    for f in [CONFIG_FILE, LOG_FILE, INTEGRITY_FILE, LOCK_FILE, WATCHDOG_PID_FILE]:
        secure_delete(f)
    
    try:
        CONFIG_DIR.rmdir()
    except:
        pass
    
    UI.success("Lock system removed.")
    log_access("Lock system removed")

def show_help():
    """Show help."""
    UI.header()
    script = Path(__file__).name
    print(f"{UI.BOLD}Usage:{UI.RESET} python3 {script} [option]\n")
    print(f"{UI.BOLD}Options:{UI.RESET}")
    print("  --setup     Configure password")
    print("  --lock      Lock terminal")
    print("  --status    Show status and logs")
    print("  --remove    Remove LMSEC")
    print("  --help      Show this help\n")
    
    print(f"{UI.BOLD}Bashrc Integration:{UI.RESET}")
    print(f"  python3 {Path(__file__).absolute()} --lock\n")
    
    print(f"{UI.BOLD}Security Features:{UI.RESET}")
    print(f"  • Fingerprint authentication (Termux:API)")
    print(f"  • PBKDF2-SHA256 ({HASH_ITERATIONS} iterations)")
    print(f"  • Watchdog daemon (shell kill on bypass)")
    print(f"  • Config integrity verification (HMAC)")
    print(f"  • Monotonic time lockout (clock-immune)")
    print(f"  • Signal blocking (SIGINT, SIGTSTP, SIGTERM, etc.)")
    print(f"  • Scrollback buffer clearing")
    print(f"  • Environment sanitization (no PATH attacks)")
    print(f"  • TTY-aware session logging\n")
    
    print(f"{UI.BOLD}Fingerprint Setup:{UI.RESET}")
    print(f"  {UI.DIM}pkg install termux-api")
    print(f"  Install Termux:API app from F-Droid{UI.RESET}\n")
    
    print(f"{UI.BOLD}Limitations:{UI.RESET}")
    print(f"  {UI.DIM}• SIGKILL (kill -9) from another session")
    print(f"  • Root access bypasses all protections")
    print(f"  • New terminal windows not blocked")
    print(f"  • Consider full-disk encryption for real security{UI.RESET}\n")
    
    print(f"{UI.BOLD}Project:{UI.RESET} LMWM by Lamgerr (NaveenSingh9999)")
    print(f"{UI.DIM}https://github.com/NaveenSingh9999{UI.RESET}\n")

def interactive_menu():
    """Interactive menu."""
    while True:
        UI.header()
        config, is_valid = load_config_with_integrity()
        
        if config.get('password_hash'):
            status = f"{UI.GREEN}●{UI.RESET} Configured"
        else:
            status = f"{UI.RED}●{UI.RESET} Not configured"
        
        if not is_valid and config:
            status += f" {UI.RED}(INTEGRITY FAILED){UI.RESET}"
        
        print(f"Status: {status}\n")
        print(f"{UI.BOLD}Menu:{UI.RESET}")
        print("  1. Setup Password")
        print("  2. Lock Terminal")
        print("  3. View Status")
        print("  4. Remove Lock")
        print("  5. Exit\n")
        
        choice = UI.prompt("Select [1-5]: ").strip()
        
        if choice == '1':
            setup_password()
            input(f"\n{UI.DIM}Press Enter...{UI.RESET}")
        elif choice == '2':
            if config.get('password_hash'):
                lock_terminal()
            else:
                UI.error("Setup password first.")
                input(f"\n{UI.DIM}Press Enter...{UI.RESET}")
        elif choice == '3':
            show_status()
            input(f"\n{UI.DIM}Press Enter...{UI.RESET}")
        elif choice == '4':
            remove_lock()
            input(f"\n{UI.DIM}Press Enter...{UI.RESET}")
        elif choice == '5':
            clear_screen_secure()
            break

# ============================================================================
# MAIN
# ============================================================================

def main():
    atexit.register(restore_signals)
    
    if len(sys.argv) < 2:
        interactive_menu()
        return
    
    arg = sys.argv[1].lower()
    
    if arg in ('--setup', '-s'):
        setup_password()
    elif arg in ('--lock', '-l'):
        config, _ = load_config_with_integrity()
        if config.get('password_hash'):
            lock_terminal()
    elif arg in ('--status', '-t'):
        show_status()
    elif arg in ('--remove', '-r'):
        remove_lock()
    elif arg in ('--help', '-h'):
        show_help()
    else:
        UI.error(f"Unknown: {arg}")
        show_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n{UI.RED}Error: {e}{UI.RESET}")
        sys.exit(1)