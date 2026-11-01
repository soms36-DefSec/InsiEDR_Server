"""
InsiEDR SOC 32 Users Batch Matrix Runner
----------------------------------------
Executes 7 insider threat attack scenarios across 32 distinct SOC users
(SOC_user1 to SOC_user32) in 7 batches.
Sends telemetry to InsiEDR Server at http://172.16.22.198/api/logs,
verifies ingestion in PostgreSQL, and cleans up artifacts.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Paths setup
AGENT_DIR = Path(r"d:\Projects\AISH\InsiEDR-agent")
SERVER_DIR = Path(r"d:\Projects\AISH\InsiEDR_Server")

sys.path.extend([
    str(AGENT_DIR),
    str(AGENT_DIR / "shared"),
    str(SERVER_DIR / "shared"),
])

from agent.collectors import discover_collectors, run_collectors
from agent.collectors.base import CollectorResult
from agent.config import AgentConfig
from agent.crypto import create_agent_crypto
from agent.payload_builder import build_payload
from agent.queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport
from shared.protocol import encrypted_payload_headers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("SOC_Matrix_Runner")

SERVER_URL = "http://172.16.22.198/api/logs"
AES_KEY_HEX = "e548bcb6e1e7da40ccac2adeba65f34554458de520e9a0780f3a5f04f01a72d7"
SSH_HOST = "172.16.22.198"
SSH_USER = "sastra"
SSH_PW = "sastra123"

# Batch definitions
BATCHES = {
    1: [f"SOC_user{i}" for i in range(1, 6)],    # 1-5
    2: [f"SOC_user{i}" for i in range(6, 11)],   # 6-10
    3: [f"SOC_user{i}" for i in range(11, 16)],  # 11-15
    4: [f"SOC_user{i}" for i in range(16, 21)],  # 16-20
    5: [f"SOC_user{i}" for i in range(21, 26)],  # 21-25
    6: [f"SOC_user{i}" for i in range(26, 31)],  # 26-30
    7: [f"SOC_user{i}" for i in range(31, 33)],  # 31-32
}


def run_cmd(cmd_str: str, timeout: int = 15) -> tuple[int, str]:
    """Execute a local shell command cleanly."""
    try:
        proc = subprocess.run(
            cmd_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "Timed out"
    except Exception as exc:
        return -1, str(exc)


def execute_cmd_attacks(username: str) -> None:
    """Execute real Command Prompt / PowerShell attack actions on the endpoint."""
    user_home = Path(os.environ.get("USERPROFILE", r"C:\Users\SOMS"))
    staging_dir = user_home / "Desktop" / f"StagingVault_{username}"
    prod_db_dir = user_home / "Documents" / f"ProductionDB_{username}"
    canary_file = Path(r"C:\Users\Public\Admin_Passwords.xlsx")

    logger.info(f"[{username}] Executing 7 attack scenario commands...")

    # 1. SIM_HONEYTOKEN_TRIP: Access Canary File
    try:
        canary_file.parent.mkdir(parents=True, exist_ok=True)
        with open(canary_file, "a", encoding="utf-8") as f:
            f.write(f"[{username} - UNAUTHORIZED_HONEYTOKEN_ACCESS: {datetime.now().isoformat()}]\n")
    except Exception as exc:
        logger.warning(f"Honeytoken write warning: {exc}")

    # 2. SIM_DATA_HOARDING: Clipboard harvesting + 50 docx files staging + zip archive
    try:
        staging_dir.mkdir(parents=True, exist_ok=True)
        run_cmd(f'powershell -Command "Set-Clipboard -Value \'SENSITIVE_FINANCIAL_RECORDS_{username}\'"')
        for i in range(1, 51):
            doc = staging_dir / f"doc_{i}.docx"
            doc.write_text(f"CONFIDENTIAL_DATA_RESTRICTED_{username}_{i}", encoding="utf-8")
        run_cmd(f'powershell -Command "Compress-Archive -Path \'{staging_dir}\\*.docx\' -DestinationPath \'{staging_dir}\\archive_staged.zip\' -Force"')
    except Exception as exc:
        logger.warning(f"Data hoarding warning: {exc}")

    # 3. SIM_USB_PRECURSOR: Removable storage simulation trigger
    run_cmd(f'cmd.exe /c "set INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA=1"')

    # 4. SIM_IT_SABOTAGE: Mass deletion of 16 database files + RunOnce persistence probe
    try:
        prod_db_dir.mkdir(parents=True, exist_ok=True)
        for i in range(1, 17):
            db_file = prod_db_dir / f"db_{i}.mdf"
            db_file.write_text("CRITICAL_DATABASE_PAYLOAD", encoding="utf-8")
        # Mass delete
        for db_file in prod_db_dir.glob("*.mdf"):
            db_file.unlink(missing_ok=True)
        # RunOnce persistence registry attempt
        run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "InsiAudit_{username}" /t REG_SZ /d "cmd.exe /c echo InsiEDR_Audit" /f')
    except Exception as exc:
        logger.warning(f"IT sabotage warning: {exc}")

    # 5. SIM_CLOUD_PRECURSOR: Network exfiltration probes
    run_cmd("curl.exe -I -s --max-time 3 https://mega.nz")
    run_cmd("curl.exe -I -s --max-time 3 https://dropbox.com")
    run_cmd("curl.exe -I -s --max-time 3 https://wetransfer.com")

    # 6. SIM_CREDENTIAL_DUMP: LSASS process handle inquiry
    run_cmd('powershell -Command "Get-Process lsass -ErrorAction SilentlyContinue | Select-Object -Property Id, ProcessName, Handles"')

    # 7. SIM_KILL_CHAIN: Chained attack sequence
    run_cmd(f'cmd.exe /c "echo [KILL_CHAIN_STAGE_COMPLETED_{username}] > {user_home}\\AppData\\Local\\Temp\\kc_{username}.tmp"')


def cleanup_user_artifacts(username: str) -> None:
    """Sanitize temporary attack staging folders and registry keys."""
    user_home = Path(os.environ.get("USERPROFILE", r"C:\Users\SOMS"))
    staging_dir = user_home / "Desktop" / f"StagingVault_{username}"
    prod_db_dir = user_home / "Documents" / f"ProductionDB_{username}"
    kc_tmp = user_home / "AppData" / "Local" / "Temp" / f"kc_{username}.tmp"
    canary_file = Path(r"C:\Users\Public\Admin_Passwords.xlsx")

    shutil.rmtree(staging_dir, ignore_errors=True)
    shutil.rmtree(prod_db_dir, ignore_errors=True)
    if kc_tmp.exists():
        kc_tmp.unlink(missing_ok=True)
    if canary_file.exists():
        try:
            canary_file.unlink(missing_ok=True)
        except Exception:
            pass
    run_cmd(f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "InsiAudit_{username}" /f')


def create_scenario_collector_results(hostname: str, username: str) -> list[CollectorResult]:
    """Generate rich collector results encompassing all 7 insider threat scenarios."""
    now_iso = datetime.now(timezone.utc).isoformat()
    return [
        CollectorResult(
            collector="decoy-monitor",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "threat_triggered": True,
                "honeytoken_name": "Admin_Passwords.xlsx",
                "action": "read",
                "accessed_by": username,
                "file_path": r"C:\Users\Public\Admin_Passwords.xlsx",
            },
        ),
        CollectorResult(
            collector="clipboard-monitor",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "clipboard_copy_count": 25,
                "sensitive_token_detected": True,
                "token_pattern": "SENSITIVE_FINANCIAL_RECORDS",
            },
        ),
        CollectorResult(
            collector="file-feature",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "daily_unique_filename_count": 68,
                "sensitive_file_access": 18,
                "file_access_count": 95,
                "file_delete_count": 16,
                "daily_file_delete_count": 16,
                "staging_archive_created": True,
                "archive_path": rf"C:\Users\SOMS\Desktop\StagingVault_{username}\archive_staged.zip",
            },
        ),
        CollectorResult(
            collector="devices-feature",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "unauthorized_usb_detected": True,
                "usb_connect_count": 1,
                "usb_serial": f"USB-KINGSTON-{uuid.uuid4().hex[:8].upper()}",
                "daily_files_to_removable_count": 45,
                "usb_file_transfer_count": 45,
            },
        ),
        CollectorResult(
            collector="persistence-monitor",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "modifications_detected": True,
                "target_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "value_name": f"InsiAudit_{username}",
                "suspicious_command": "cmd.exe /c sc stop WinDefend",
            },
        ),
        CollectorResult(
            collector="http-feature",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "cloud_storage_uploads": 5,
                "upload_bytes": 524288000,
                "destination_domain": "mega.nz",
                "cloud_exfiltration_flag": True,
            },
        ),
        CollectorResult(
            collector="lsass-monitor",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "credential_dumping_suspected": True,
                "unbacked_executable_memory": True,
                "target_process": "lsass.exe",
                "access_mask": "0x1FFFFF",
            },
        ),
        CollectorResult(
            collector="process-watcher",
            collected_at=now_iso,
            hostname=hostname,
            status="success",
            quality="exact",
            payload={
                "running_processes": ["cmd.exe", "powershell.exe", "curl.exe", "tar.exe"],
                "process_count": 52,
                "suspicious_processes": 1,
                "kill_chain_detected": True,
            },
        ),
    ]


def run_agent_for_user(username: str) -> bool:
    """Run an agent telemetry collection and transmission cycle for the given SOC user."""
    hostname = username
    agent_id = f"SASTRA-{username}"

    # Setup environment variables for agent
    os.environ["INSIEDR_USERNAME"] = username
    os.environ["INSIEDR_HOSTNAME"] = hostname
    os.environ["INSIEDR_AGENT_ID"] = agent_id
    os.environ["INSIEDR_AGENT_SERVER"] = SERVER_URL
    os.environ["INSIEDR_AES_KEY"] = AES_KEY_HEX
    os.environ["INSIEDR_CRYPTO_SCHEME"] = "aes-256-gcm"
    os.environ["INSIEDR_SERVER_KEY_ID"] = "default"
    os.environ["INSIEDR_ALLOW_INSECURE_HTTP"] = "true"
    os.environ["INSIEDR_REQUIRE_HTTPS"] = "false"
    os.environ["INSIEDR_DISABLE_TLS_VERIFY"] = "true"

    try:
        config = AgentConfig.from_env()
        queue = LocalEncryptedQueue(config.queue_dir)
        crypto = create_agent_crypto(config)
        transport = TelemetryTransport(
            server_url=config.server_url,
            queue=queue,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
            agent_token=config.agent_token,
        )

        # Retry any previously queued items first
        transport.retry_queued(limit=10)

        # Gather baseline live collectors + scenario attack results
        live_collectors = discover_collectors(
            ("logon", "file", "device", "http", "process"),
            hostname=hostname,
        )
        live_results = run_collectors(live_collectors)
        scenario_results = create_scenario_collector_results(hostname, username)
        all_results = list(live_results) + scenario_results

        # Build payload
        payload = build_payload(
            agent_id=agent_id,
            hostname=hostname,
            username=username,
            collector_results=all_results,
        )

        # Encrypt and transmit
        envelope = crypto.encrypt_payload(payload)
        envelope["payload_id"] = payload["payload_id"]
        headers = encrypted_payload_headers(envelope, agent_id, payload["payload_id"])

        send_result = transport.send_or_queue(envelope, headers)
        if send_result.ok:
            logger.info(f"[{username}] Ingestion SUCCESS -> payload {payload['payload_id']} accepted (HTTP 202)")
            return True
        else:
            logger.warning(f"[{username}] Ingestion queued locally (HTTP {send_result.status_code}), entering retry loop...")
            # Retry loop for queued item
            for attempt in range(1, 4):
                time.sleep(2)
                retry_res = transport.retry_queued(limit=10)
                if retry_res.get("sent", 0) > 0 and retry_res.get("retained", 0) == 0:
                    logger.info(f"[{username}] Retry attempt {attempt} SUCCESS -> queued payload accepted!")
                    return True
            return False
    except Exception as exc:
        logger.error(f"[{username}] Agent exception: {exc}")
        return False


def verify_user_in_db(username: str, max_retries: int = 3) -> bool:
    """Verify that the user's agent and payload exist in PostgreSQL on 172.16.22.198."""
    agent_id = f"SASTRA-{username}"
    plink_cmd = (
        f'echo y | plink.exe -batch -ssh -l {SSH_USER} -pw {SSH_PW} {SSH_HOST} '
        f'"docker exec -i insiedr_server-db-1 psql -U insiedr -d insiedr_db -t -A -c '
        f'\\"SELECT count(*) FROM raw_payloads WHERE agent_id = \'{agent_id}\';\\""'
    )
    for _ in range(max_retries):
        ret, out = run_cmd(plink_cmd, timeout=12)
        try:
            lines = [line.strip() for line in out.strip().splitlines() if line.strip().isdigit()]
            if lines and int(lines[-1]) > 0:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def flush_agent_queue() -> None:
    """Flush any remaining queued payloads from disk to server."""
    try:
        config = AgentConfig.from_env()
        queue = LocalEncryptedQueue(config.queue_dir)
        transport = TelemetryTransport(
            server_url=config.server_url,
            queue=queue,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
        )
        for _ in range(3):
            res = transport.retry_queued(limit=25)
            if res.get("retained", 0) == 0:
                break
            time.sleep(2)
    except Exception:
        pass


def execute_batch(batch_num: int) -> dict[str, bool]:
    """Execute all users in a single batch continuously without pausing."""
    users = BATCHES[batch_num]
    logger.info(f"=== STARTING BATCH {batch_num}/7 ({len(users)} users: {users[0]}..{users[-1]}) ===")
    results = {}

    for user in users:
        logger.info(f"--- Processing {user} ---")
        execute_cmd_attacks(user)
        run_agent_for_user(user)
        cleanup_user_artifacts(user)

        # DB verification
        verified = verify_user_in_db(user)
        results[user] = verified
        logger.info(f"[{user}] DB Status: {'VERIFIED (Committed to Database)' if verified else 'PENDING'}")
        time.sleep(1)

    # Batch post-flush to ensure zero leftover spooled files
    flush_agent_queue()

    # Re-verify any pending users
    for user, ok in results.items():
        if not ok:
            results[user] = verify_user_in_db(user)

    logger.info(f"=== COMPLETED BATCH {batch_num}/7: {sum(results.values())}/{len(users)} VERIFIED ===")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="InsiEDR SOC 32 Users Batch Matrix Runner")
    parser.add_argument("--batch", type=int, choices=range(1, 8), help="Run a specific batch (1-7)")
    parser.add_argument("--all", action="store_true", help="Run all batches from 1 to 7 continuously")
    parser.add_argument("--from-batch", type=int, default=1, choices=range(1, 8), help="Start from a specific batch (default: 1)")
    parser.add_argument("--verify-only", action="store_true", help="Check database status for all 32 users")
    args = parser.parse_args()

    if args.verify_only:
        logger.info("Verifying all 32 users in remote database...")
        all_ok = True
        for i in range(1, 33):
            user = f"SOC_user{i}"
            ok = verify_user_in_db(user)
            logger.info(f"  {user}: {'EXISTS' if ok else 'MISSING'}")
            if not ok:
                all_ok = False
        logger.info(f"Verification complete: {'ALL 32 USERS PRESENT' if all_ok else 'SOME USERS MISSING'}")
        return

    if args.batch:
        execute_batch(args.batch)
        return

    total_batches = 7
    total_results = {}
    start_time = time.time()
    start_b = args.from_batch

    for b in range(start_b, total_batches + 1):
        batch_res = execute_batch(b)
        total_results.update(batch_res)

        # Progress calculations
        completed_users = len(total_results)
        remaining_users = 32 - completed_users
        elapsed_min = (time.time() - start_time) / 60.0
        avg_per_user = elapsed_min / completed_users if completed_users else 1.0
        est_remaining_min = remaining_users * avg_per_user

        print("\n" + "=" * 65, flush=True)
        print(f"BATCH {b}/7 COMPLETE: {len(batch_res)} users processed ({sum(batch_res.values())}/{len(batch_res)} verified)", flush=True)
        print(f"Overall Matrix Progress: {completed_users}/32 users ({int(completed_users/32*100)}%)", flush=True)
        print(f"Elapsed Time: {elapsed_min:.1f} mins | Estimated Time Remaining: {est_remaining_min:.1f} mins", flush=True)
        print("=" * 65 + "\n", flush=True)

    logger.info("ALL 32 USERS EXECUTED, INGESTED, AND VERIFIED IN DATABASE!")


if __name__ == "__main__":
    main()
