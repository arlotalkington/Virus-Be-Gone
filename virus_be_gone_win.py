import cmd
import os
import time
import json
import shutil
import hashlib
import subprocess
import threading
from datetime import datetime
from colorama import Fore, init
from win32 import win32security
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

init(autoreset=True)
sigs = set()
ALL_ACCESS = 0x1F01FF  # full access mask

# === Dynamic base paths relative to this script ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNATURES_PATH = os.path.join(BASE_DIR, "signatures")
QUARANTINE_PATH = os.path.join(BASE_DIR, "quarantine")

def hash_file(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        print(Fore.GREEN + f"✔️ Hashed: {filepath}")
        return sha256.hexdigest()
    except Exception as e:
        print(Fore.RED + f"❌ Failed to hash {filepath}: {e}")
        return None

def load_sigs():
    local_sigs = set()
    if not os.path.exists(SIGNATURES_PATH):
        print(Fore.RED + "🚫 Signature folder not found!")
        return local_sigs

    for filename in os.listdir(SIGNATURES_PATH):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(SIGNATURES_PATH, filename), 'r') as f:
                    data = json.load(f)
                    for entry in data:
                        sig = entry.get("hash")
                        if sig:
                            local_sigs.add(sig.strip())
                print(Fore.GREEN + f"Loaded signatures from {filename}")
            except json.JSONDecodeError as e:
                print(Fore.RED + f"Error loading {filename}: Invalid JSON format - {e}")
            except Exception as e:
                print(Fore.RED + f"Error loading {filename}: {e}")
    
    print(Fore.YELLOW + f"🔍 Total signatures: {len(local_sigs)}")
    return local_sigs

def clear_console():
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)

def quarantine_file(filepath, sig_hash):
    log_file = os.path.join(QUARANTINE_PATH, "quarantine_log.json")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    base_name = os.path.basename(filepath)
    target_path = os.path.join(QUARANTINE_PATH, base_name)

    try:
        os.makedirs(QUARANTINE_PATH, exist_ok=True)
        shutil.move(filepath, target_path)

        everyone, _, _ = win32security.LookupAccountName("", "Everyone")
        dacl = win32security.ACL()
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, ALL_ACCESS, everyone)
        sd = win32security.GetFileSecurity(target_path, win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(target_path, win32security.DACL_SECURITY_INFORMATION, sd)

        entry = {
            "original_path": filepath,
            "quarantined_as": target_path,
            "hash": sig_hash,
            "timestamp": timestamp
        }

        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                data = json.load(f)
        else:
            data = []

        data.append(entry)

        with open(log_file, "w") as f:
            json.dump(data, f, indent=2)

        print(Fore.MAGENTA + f"📦 Quarantined: {filepath}")

    except Exception as e:
        print(Fore.RED + f"⚠️ Failed to quarantine: {e}")

def manual_quarantine(filepath):
    if not os.path.exists(filepath):
        print(Fore.RED + f"File not found: {filepath}")
        return
    file_hash = hash_file(filepath)
    if file_hash:
        quarantine_file(filepath, file_hash)

def list_quarantine():
    log_file = os.path.join(QUARANTINE_PATH, "quarantine_log.json")
    if not os.path.exists(log_file):
        print(Fore.YELLOW + "🟡 No quarantine log found.")
        return

    with open(log_file, "r") as f:
        data = json.load(f)

    if not data:
        print(Fore.GREEN + "✅ Quarantine is empty.")
        return

    print(Fore.CYAN + "\n📂 Quarantined Files:")
    for entry in data:
        print(Fore.MAGENTA + f"- {os.path.basename(entry['quarantined_as'])} | Original: {entry['original_path']} | Time: {entry['timestamp']}")

def restore_file(filename):
    full_path = os.path.join(QUARANTINE_PATH, filename)
    log_file = os.path.join(QUARANTINE_PATH, "quarantine_log.json")

    print(f"Attempting to restore: {filename}")
    print(f"Full quarantined path: {full_path}")

    if not os.path.exists(full_path):
        print(Fore.RED + f"File not found in quarantine: {filename}")
        return

    try:
        everyone, _, _ = win32security.LookupAccountName("", "Everyone")
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ALL_ACCESS, everyone)
        sd = win32security.GetFileSecurity(full_path, win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(full_path, win32security.DACL_SECURITY_INFORMATION, sd)
        print(Fore.GREEN + "✅ Permissions reset to allow Everyone.")

        with open(log_file, "r") as f:
            data = json.load(f)

        restored = False
        for entry in data:
            if os.path.basename(entry["quarantined_as"]) == filename:
                original_path = entry["original_path"]
                print(f"Original path found in log: {original_path}")
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                print(f"Moving {full_path} -> {original_path}")
                shutil.move(full_path, original_path)
                data.remove(entry)
                restored = True
                print(Fore.YELLOW + f"🧹 Restored: {original_path}")
                break

        if not restored:
            print(Fore.RED + "No matching log entry found to restore.")

        with open(log_file, "w") as f:
            json.dump(data, f, indent=2)

    except Exception as e:
        print(Fore.RED + f"⚠️ Failed to restore: {e}")

def delete_quarantined_file(filename):
    full_path = os.path.join(QUARANTINE_PATH, filename)
    log_file = os.path.join(QUARANTINE_PATH, "quarantine_log.json")

    if not os.path.exists(full_path):
        print(Fore.RED + f"File not found in quarantine: {filename}")
        return

    try:
        os.remove(full_path)
        print(Fore.RED + f"🗑️ Deleted: {filename}")

        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                data = json.load(f)
            data = [entry for entry in data if os.path.basename(entry["quarantined_as"]) != filename]
            with open(log_file, "w") as f:
                json.dump(data, f, indent=2)

    except Exception as e:
        print(Fore.RED + f"⚠️ Failed to delete: {e}")

def do_full_scan(start_path="C:\\"):
    print(Fore.CYAN + f"🔍 Scanning: {start_path}")
    infected = []
    count = 0

    for root, _, files in os.walk(start_path):
        for name in files:
            filepath = os.path.join(root, name)
            count += 1
            file_hash = hash_file(filepath)
            if file_hash and file_hash in sigs:
                quarantine_file(filepath, file_hash)
                infected.append(filepath)

    print(Fore.YELLOW + f"\nTotal files scanned: {count}")
    if infected:
        print(Fore.RED + f"Infected files found: {len(infected)}")
    else:
        print(Fore.GREEN + "No infected files found.")

def do_quick_scan(start_path="C:\\", max_files=500):
    print(Fore.CYAN + f"⚡ Quick scanning: {start_path} (up to {max_files} files)")
    infected = []
    count = 0

    for root, _, files in os.walk(start_path):
        for name in files:
            if count >= max_files:
                break
            filepath = os.path.join(root, name)
            count += 1
            file_hash = hash_file(filepath)
            if file_hash and file_hash in sigs:
                quarantine_file(filepath, file_hash)
                infected.append(filepath)
        if count >= max_files:
            break

    print(Fore.YELLOW + f"\n📁 Files scanned in quick scan: {count}")
    if infected:
        print(Fore.RED + f"❗ Infected files found: {len(infected)}")
    else:
        print(Fore.GREEN + "✅ No infected files found in quick scan.")

def do_custom_scan(start_path="C:\\", max_files=1000):
    print(Fore.CYAN + f"🛠️ Custom scanning: {start_path} (up to {max_files} files)")
    infected = []
    count = 0

    for root, _, files in os.walk(start_path):
        for name in files:
            if count >= max_files:
                break
            filepath = os.path.join(root, name)
            count += 1
            file_hash = hash_file(filepath)
            if file_hash and file_hash in sigs:
                quarantine_file(filepath, file_hash)
                infected.append(filepath)
        if count >= max_files:
            break

    print(Fore.YELLOW + f"\n📁 Files scanned in custom scan: {count}")
    if infected:
        print(Fore.RED + f"❗ Infected files found: {len(infected)}")
    else:
        print(Fore.GREEN + "✅ No infected files found in custom scan.")

class ScanEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"🆕 New file detected: {event.src_path}")
            file_hash = hash_file(event.src_path)
            if file_hash and file_hash in sigs:
                quarantine_file(event.src_path, file_hash)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"✏️ File modified: {event.src_path}")
            file_hash = hash_file(event.src_path)
            if file_hash and file_hash in sigs:
                quarantine_file(event.src_path, file_hash)

def start_realtime_monitor(path="C:\\"):
    event_handler = ScanEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"👁️ Watching {path} for file changes...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

class vbg(cmd.Cmd):
    intro = Fore.GREEN + "🛡️ Virus Be Gone - Type 'help' or '?' For Commands 🛡️"
    prompt = Fore.YELLOW + "< (Virus Be Gone) > "
    os.system("title Virus Be Gone")

    def do_help(self, arg):
        print(Fore.CYAN + "\n🔧 Commands:")
        print(Fore.YELLOW + "scan --full" + Fore.WHITE + "         → Full system scan")
        print(Fore.YELLOW + "scan --quick [path]" + Fore.WHITE + "  → Quick scan (default C:\\)")
        print(Fore.YELLOW + "scan --custom [path] [max_files]" + Fore.WHITE + " → Custom scan with limits")
        print(Fore.YELLOW + "quarantine <path>" + Fore.WHITE + "   → Manually quarantine file")
        print(Fore.YELLOW + "quarantines" + Fore.WHITE + "        → List quarantined files")
        print(Fore.YELLOW + "restore <filename>" + Fore.WHITE + " → Restore file from quarantine")
        print(Fore.YELLOW + "delete <filename> / --all" + Fore.WHITE + " → Delete specific or all quarantined files")
        print(Fore.YELLOW + "reload_sigs" + Fore.WHITE + "        → Reload virus signatures")
        print(Fore.YELLOW + "clear" + Fore.WHITE + "              → Clear the terminal")
        print(Fore.YELLOW + "exit" + Fore.WHITE + "               → Exit the program")

    def do_scan(self, arg):
        args = arg.split()
        if len(args) == 0:
            print(Fore.YELLOW + "Please specify scan mode: --full, --quick, or --custom")
            return

        mode = args[0]

        if mode == "--full":
            start_path = args[1] if len(args) > 1 else "C:\\"
            do_full_scan(start_path)

        elif mode == "--quick":
            start_path = args[1] if len(args) > 1 else "C:\\"
            do_quick_scan(start_path)

        elif mode == "--custom":
            start_path = args[1] if len(args) > 1 else "C:\\"
            try:
                max_files = int(args[2]) if len(args) > 2 else 1000
            except ValueError:
                print(Fore.RED + "Invalid max_files parameter, must be an integer.")
                return
            do_custom_scan(start_path, max_files)

        else:
            print(Fore.RED + f"Unknown scan mode: {mode}")

    def do_quarantine(self, arg):
        manual_quarantine(arg.strip())

    def do_quarantines(self, arg):
        list_quarantine()

    def do_restore(self, arg):
        restore_file(arg.strip())

    def do_delete(self, arg):
        if arg.strip() == "--all":
            log_file = os.path.join(QUARANTINE_PATH, "quarantine_log.json")

            if not os.path.exists(log_file):
                print(Fore.YELLOW + "🟡 No quarantine log found.")
                return

            try:
                with open(log_file, "r") as f:
                    data = json.load(f)

                for entry in data:
                    filename = os.path.basename(entry["quarantined_as"])
                    full_path = os.path.join(QUARANTINE_PATH, filename)
                    if os.path.exists(full_path):
                        os.remove(full_path)
                        print(Fore.RED + f"🗑️ Deleted: {filename}")

                with open(log_file, "w") as f:
                    json.dump([], f)

                print(Fore.GREEN + "✅ All quarantined files deleted.")

            except Exception as e:
                print(Fore.RED + f"⚠️ Failed to delete all: {e}")
        else:
            delete_quarantined_file(arg.strip())

    def do_reload_sigs(self, arg):
        global sigs
        sigs = load_sigs()

    def do_clear(self, arg):
        clear_console()

    def do_exit(self, arg):
        print(Fore.GREEN + "👋 Exiting Virus Be Gone.")
        return True

    def do_monitor(self, arg):
        """Starts Real-Time File Monitoring"""
        path = arg.strip() or "C:\\"
        print(Fore.CYAN + f"Starting real-time monitor on {path}")
        monitor_thread = threading.Thread(target=start_realtime_monitor, args=(path,), daemon=True)
        monitor_thread.start()

if __name__ == "__main__":
    sigs = load_sigs()
    vbg().cmdloop()
