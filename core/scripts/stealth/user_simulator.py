# user_activity_simulator.py
"""
Simulate light, human‑like user activity inside a Windows guest.
Use this after the VM boots and you have installed Python 3.x plus
`pip install pyautogui psutil` inside the guest.

Features
--------
* Random mouse movement & clicks
* Typing in Notepad
* Browsing a short list of websites in the default browser
* Opening File Explorer and navigating to common folders
* Randomised timing & jitter to avoid robotic patterns
* Graceful exit on Ctrl‑C

Run with:
    python user_activity_simulator.py --duration 900  # 15 minutes

You can also import and call `simulate_activity()` from your own scripts.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import random
import subprocess
import sys
import time
from pathlib import Path

import pyautogui as pag

pag.FAILSAFE = True  # move mouse to corner to abort

# ----------------------------------------------------------------------------
# Helper primitives
# ----------------------------------------------------------------------------

def _rand_delay(min_s: float = 0.5, max_s: float = 2.0):
    """Sleep for a random interval within [min_s, max_s] seconds."""
    time.sleep(random.uniform(min_s, max_s))


def _type_text(text: str):
    for ch in text:
        pag.typewrite(ch)
        time.sleep(random.uniform(0.05, 0.25))
    _rand_delay()


def _move_mouse_random():
    width, height = pag.size()
    for _ in range(random.randint(3, 7)):
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        pag.moveTo(x, y, duration=random.uniform(0.3, 1.2))
        if random.random() < 0.3:
            pag.click()
        _rand_delay(0.2, 1.0)

# ----------------------------------------------------------------------------
# Activity modules
# ----------------------------------------------------------------------------

def open_notepad_and_type():
    subprocess.Popen(["notepad.exe"])
    _rand_delay(1.0, 2.5)
    pag.hotkey("win", "up")  # maximise window
    sample_sentences = [
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "This is a test sentence for malware evasion.",
        f"Current time: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}",
        "The quick brown fox jumps over the lazy dog.",
    ]
    for sentence in random.sample(sample_sentences, k=len(sample_sentences)):
        _type_text(sentence + "\n")
    _rand_delay(0.5, 1.5)
    pag.hotkey("ctrl", "s")
    _rand_delay(0.5, 1.0)
    _type_text(str(Path.home() / "Desktop" / "notes.txt"))
    pag.press("enter")
    _rand_delay(1.0, 1.5)
    pag.hotkey("alt", "f4")


def browse_websites():
    urls = [
        "https://www.bing.com",
        "https://news.ycombinator.com",
        "https://www.wikipedia.org",
        "https://www.reddit.com/r/windows11",
    ]
    random.shuffle(urls)
    for url in urls:
        subprocess.Popen(["cmd", "/c", "start", "", url])
        _rand_delay(3.0, 6.0)
        _move_mouse_random()
        _rand_delay(2.0, 5.0)
    pag.hotkey("alt", "f4")


def open_explorer_and_browse():
    subprocess.Popen(["explorer.exe", str(Path.home())])
    _rand_delay(1.5, 3.0)
    pag.hotkey("win", "up")
    for folder in ["Documents", "Pictures", "Downloads"]:
        pag.typewrite(folder)
        pag.press("enter")
        _rand_delay(1.5, 3.0)
        _move_mouse_random()
        pag.hotkey("alt", "left")
        _rand_delay(1.0, 2.0)
    pag.hotkey("alt", "f4")

# ----------------------------------------------------------------------------
# Main driver
# ----------------------------------------------------------------------------

def simulate_activity(duration_seconds: int = 900):
    """Run random activity blocks until `duration_seconds` elapse."""
    actions = [open_notepad_and_type, browse_websites, open_explorer_and_browse, _move_mouse_random]
    end_time = time.time() + duration_seconds
    while time.time() < end_time:
        random.choice(actions)()
        _rand_delay(2.0, 5.0)


def _parse_args():
    p = argparse.ArgumentParser(description="Simulate human‑like activity in a Windows VM.")
    p.add_argument("--duration", type=int, default=900, help="Duration in seconds (default: 900)")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        simulate_activity(args.duration)
    except KeyboardInterrupt:
        print("\n[+] User activity simulation interrupted by user, exiting…")
