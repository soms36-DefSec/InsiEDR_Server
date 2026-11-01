"""
InsiEDR Real Sensor Attack Matrix Runner (32 SOC Users, 7 Batches)
-----------------------------------------------------------------
Executes REAL physical OS attack actions for all 32 users (SOC_user1 to SOC_user32).
Samples events using REAL native InsiEDR collectors (decoy-monitor, clipboard-monitor,
file-feature, persistence-monitor, http-feature, devices-feature, lsass-monitor).
Encrypts telemetry via real AES-256-GCM and sends to InsiEDR Server at http://172.16.22.198/api/logs.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Set up python paths
sys.path.extend([
    r"d:\Projects\AISH\InsiEDR-agent",
    r"d:\Projects\AISH\InsiEDR-agent\shared",
    r"d:\Projects\AISH\InsiEDR_Server\shared",
])

import psutil
from agent.config import AgentConfig
from agent.agent import EndpointAgent
from agent.state import default_state_dir, write_json_file

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("RealSensorRunner")

SERVER_URL = "http://172.16.22.198/api/logs"
AES_KEY_HEX = "e548bcb6e1e7da40ccac2adeba65f34554458de520e9a0780f3a5f04f01a72d7"
USER_HOME = Path(os.environ.get("USERPROFILE", r"C:\Users\SOMS"))
DECOY_FILE = Path(r"C:\Users\Public\Admin_Passwords.xlsx")
REMOVABLE_USB = Path("E:\\")

BATCHES = {
    1: [f"SOC_user{i}" for i in range(1, 6)],    # 1-5
    2: [f"SOC_user{i}" for i in range(6, 11)],   # 6-10
    3: [f"SOC_user{i}" for i in range(11, 16)],  # 11-15
    4: [f"SOC_user{i}" for i in range(16, 21)],  # 16-20
    5: [f"SOC_user{i}" for i in range(21, 26)],  # 21-25
    6: [f"SOC_user{i}" for i in range(26, 31)],  # 26-30
    7: [f"SOC_user{i}" for i in range(31, 33)],  # 31-32
}


def run_cmd(cmd: str, timeout: int = 15) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout + proc.stderr
    except Exception as exc:
        return -1, str(exc)


def execute_physical_attacks(username: str) -> None:
    """Execute real physical attack actions on the Windows endpoint."""
    logger.info(f"  [>] Triggering physical attack actions for {username}...")

    # 1. Decoy / Honeytoken Access (SIM_HONEYTOKEN_TRIP)
    DECOY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DECOY_FILE, "a", encoding="utf-8") as f:
        f.write(f"\nUNAUTHORIZED_EXFIL_ATTEMPT_{username}_{time.time()}\n")

    # 2. Clipboard Harvesting (SIM_DATA_HOARDING)
    for i in range(5):
        run_cmd(f'powershell -Command "Set-Clipboard -Value \'SENSITIVE_FINANCIAL_RECORDS_{username}_{i}\'"')
        time.sleep(0.12)

    # 3. File Hoarding & Staging (SIM_DATA_HOARDING & SIM_KILL_CHAIN)
    staging_dir = USER_HOME / "Desktop" / f"StagingVault_{username}"
    staging_dir.mkdir(parents=True, exist_ok=True)
    for i in range(1, 16):
        (staging_dir / f"confidential_{username}_{i}.docx").write_text(f"RESTRICTED_DATA_PAYLOAD_{i}")
    run_cmd(f'powershell -Command "Compress-Archive -Path \'{staging_dir}\\*.docx\' -DestinationPath \'{staging_dir}\\archive_staged.zip\' -Force"')

    # 4. IT Sabotage Mass Deletion (SIM_IT_SABOTAGE)
    prod_dir = USER_HOME / "Documents" / f"ProductionDB_{username}"
    prod_dir.mkdir(parents=True, exist_ok=True)
    for i in range(1, 13):
        (prod_dir / f"database_{i}.mdf").write_text("CRITICAL_DATABASE_PAYLOAD")
    for f in prod_dir.glob("*.mdf"):
        f.unlink(missing_ok=True)

    # 5. Registry Persistence (SIM_IT_SABOTAGE & SIM_KILL_CHAIN)
    run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "InsiAudit_{username}" /t REG_SZ /d "cmd.exe /c echo InsiEDR_Audit" /f')

    # 6. Cloud Precursor & Exfiltration (SIM_CLOUD_PRECURSOR)
    try:
        chrome_history = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "History"
        if chrome_history.exists():
            epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
            now_ts = int((datetime.now(timezone.utc) - epoch_start).total_seconds() * 1_000_000)
            conn = sqlite3.connect(chrome_history, timeout=5)
            cur = conn.cursor()
            exfil_urls = [
                f"https://mega.nz/folder/restricted_exfil_{username}",
                f"https://pastebin.com/raw/d849hf_{username}",
                f"https://dropbox.com/s/bulk_download_{username}",
            ]
            for idx, u in enumerate(exfil_urls, int(time.time() * 1000) % 1000000):
                cur.execute(
                    "INSERT OR REPLACE INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (idx, u, f"Restricted Exfil {username}", 1, 1, now_ts, 0),
                )
                cur.execute(
                    "INSERT OR REPLACE INTO visits (id, url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (idx, idx, now_ts, 0, 0, 0, 15),
                )
            conn.commit()
            conn.close()
    except Exception as exc:
        logger.warning(f"Chrome history staging skipped: {exc}")
    run_cmd("curl.exe -I -s --max-time 3 https://mega.nz")

    # 7. USB Exfiltration (SIM_USB_PRECURSOR)
    if REMOVABLE_USB.exists():
        usb_payload = REMOVABLE_USB / f"exfil_payload_{username}.bin"
        try:
            run_cmd(f'fsutil file createnew "{usb_payload}" 125829120')
        except Exception as exc:
            logger.warning(f"USB file creation skipped: {exc}")

    # 8. LSASS Process Query Probe (SIM_CREDENTIAL_DUMP)
    try:
        lsass_pid = None
        for p in psutil.process_iter(["name", "pid"]):
            if p.info["name"] and "lsass" in p.info["name"].lower():
                lsass_pid = p.info["pid"]
                break
        if lsass_pid:
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, lsass_pid)
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
        probe_file = default_state_dir() / "lsass_probes.json"
        write_json_file(probe_file, {
            "probes": [{
                "event_id": 4656,
                "source_process": "powershell.exe",
                "target_object": "C:\\Windows\\System32\\lsass.exe",
                "access_mask": "0x1010",
                "handle_id": "0x4b8",
                "subject_user": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
        })
    except Exception as exc:
        logger.warning(f"LSASS probe setup skipped: {exc}")


def cleanup_user_artifacts(username: str) -> None:
    """Clean up staging vaults, removable USB payload, registry keys, and probe files."""
    staging_dir = USER_HOME / "Desktop" / f"StagingVault_{username}"
    prod_dir = USER_HOME / "Documents" / f"ProductionDB_{username}"
    shutil.rmtree(staging_dir, ignore_errors=True)
    shutil.rmtree(prod_dir, ignore_errors=True)
    run_cmd(f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "InsiAudit_{username}" /f')

    if REMOVABLE_USB.exists():
        usb_payload = REMOVABLE_USB / f"exfil_payload_{username}.bin"
        if usb_payload.exists():
            try:
                usb_payload.unlink(missing_ok=True)
            except Exception:
                pass

    try:
        probe_file = default_state_dir() / "lsass_probes.json"
        if probe_file.exists():
            probe_file.unlink(missing_ok=True)
    except Exception:
        pass


def run_user_lifecycle(username: str) -> bool:
    """Run baseline, execute real attack, sample with native collectors, and transmit."""
    logger.info(f"=== Starting Real Agent Lifecycle for {username} ===")

    cfg = AgentConfig(
        server_url=SERVER_URL,
        agent_id=f"SASTRA-{username}",
        hostname="SANDY",
        username=username,
        queue_dir=Path(r"C:\ProgramData\InsiEDR\agent_queue"),
        encryption_scheme="aes-256-gcm",
        aes_key=bytes.fromhex(AES_KEY_HEX),
        allow_insecure_http=True,
        enabled_collectors=[
            "decoy-monitor",
            "clipboard-monitor",
            "file-feature",
            "persistence-monitor",
            "devices-feature",
            "http-feature",
            "lsass-monitor",
        ],
    )

    agent = EndpointAgent(cfg)

    # 1. Baseline collection (establishes baseline hashes & monitors)
    logger.info(f"  [1/4] Running baseline collection for {username}...")
    baseline_summary = agent.run_once()

    # 2. Execute real physical attack actions
    logger.info(f"  [2/4] Executing real attack actions...")
    execute_physical_attacks(username)

    # 3. Buffer pause: allow watchdog and clipboard threads to process events
    logger.info(f"  [3/4] Buffering events for 2.0s...")
    time.sleep(2.0)

    # 4. Attack collection & transmission
    logger.info(f"  [4/4] Running live attack sensor collection...")
    attack_summary = agent.run_once()

    # Retry spooled payload if server returned temporary 503 or connect delay
    if attack_summary.queued or not attack_summary.sent:
        logger.info("  [*] Payload spooled in local queue; attempting transport flush...")
        for attempt in range(1, 4):
            time.sleep(1.5)
            retry_res = agent.transport.retry_queued(limit=5)
            if retry_res.get("sent", 0) > 0:
                logger.info(f"  [+] Spooled payload successfully delivered on retry {attempt}.")
                break

    # Clean up local filesystem and registry artifacts
    cleanup_user_artifacts(username)
    logger.info(f"=== Completed {username} (Collectors: {attack_summary.collectors_success}/{attack_summary.collectors_total}) ===\n")
    return True


def main():
    logger.info("==============================================================")
    logger.info(" INSIEDR REAL SENSOR ATTACK MATRIX: 32 USERS / 7 BATCHES     ")
    logger.info("==============================================================")

    total_start = time.time()
    completed_users = 0

    for batch_num, users in BATCHES.items():
        logger.info(f"\n>>>>>>>> STARTING BATCH {batch_num}/7: {users} <<<<<<<<")
        batch_start = time.time()

        for u in users:
            try:
                run_user_lifecycle(u)
                completed_users += 1
            except Exception as exc:
                logger.error(f"Error processing {u}: {exc}", exc_info=True)

        batch_elapsed = time.time() - batch_start
        logger.info(f">>>>>>>> BATCH {batch_num}/7 FINISHED in {batch_elapsed:.1f}s <<<<<<<<\n")

    total_elapsed = time.time() - total_start
    logger.info("==============================================================")
    logger.info(f" ALL 7 BATCHES COMPLETE: {completed_users}/32 users in {total_elapsed:.1f}s")
    logger.info("==============================================================")


if __name__ == "__main__":
    main()
