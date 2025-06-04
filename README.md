# 🛡️ Virus Be Gone

**Virus Be Gone** is a command-line antivirus scanner packaged as a standalone `.exe`. It features full, quick, and custom scan modes, real-time monitoring, signature-based detection, quarantine, and file recovery — all in one file.

## 🔧 Features
- ✅ Full system scans (`--full`)
- ⚡ Quick scans of key user folders (`--quick`)
- 🎯 Custom scans with file limits (`--custom`)
- 🧬 Signature-based detection (`signatures/`)
- 📦 Quarantine system with logging
- 🔄 Real-time file monitoring
- ♻️ Restore or delete quarantined files
- 🎛️ Interactive command shell with color output

## 📁 Quarantine
Files detected by signature are moved into a secure `quarantine/` folder and locked using Windows file permissions. You can view, restore, or permanently delete files.

## 📂 Signature Format
Signature files are stored as JSON in the `signatures/` folder:

```json
[
  { "hash": "e3b0c44298fc1c149afbf4c8996fb924..." }
]
```

## 🚀 Getting Started

Just run the `.exe` file:

```bash
virus_be_gone.exe
```

or
```powershell
.\virus_be_gone_win.exe
```

Inside the app, type `help` to explore available commands.

## 📌 Topics
`#antivirus` `#python` `#exe` `#cli` `#security` `#quarantine`  
`#hash-scanner` `#cybersecurity` `#realtime-monitoring` `#open-source`

---

> Built with ❤️ by Arlo. Virus go bye-bye.
