# easyssh

> **One-command PowerShell wizard that turns a fresh Windows PC into a securely reachable node—sets up admin user, RDP, OpenSSH, Tailscale & ready-made client scripts.**

---

## ✨ What it does

1. **Creates or updates** a local administrator account ­— you choose the username & password interactively.  
2. **Enables Remote Desktop (RDP)** and opens the correct firewall rules.  
3. **Installs / starts OpenSSH** so you can SSH into the box.  
4. **Installs / revives Tailscale** (or skips if it’s already installed) and brings the interface *up* unattended.  
5. **Generates three helper artefacts** named after the user and Tailnet IP/DNS:

| File | Purpose |
|------|---------|
| `host_setup_<user>_<ip>.ps1` | Rerunnable host-side setup (idempotent) |
| `client_use_<user>_<ip>.ps1` | Client helper that opens an SSH tunnel **or** launches RDP |
| `<user>_<ip>.rdp` | Double-click for a one-shot RDP session |

All activity is logged to `build_YYYYMMDD_HHMMSS.log` for easy auditing.

---

## 📋 Requirements

| Machine | OS | Rights | Extras |
|---------|----|--------|--------|
| **Host PC** (the box you’re provisioning) | Windows 10/11 *or* Windows Server 2016+ | Must run scripts with **Administrator** privileges | Internet access to download Tailscale if absent |
| **Client PC** (your workstation) | Windows 10/11, macOS or Linux | Standard user OK | Needs `ssh` if you choose tunnel mode |

---

## 🚀 Quick start

### 1. Clone / download

download the file easy_ssh.ps1 and put it where you want (other scripts will be created in the same folfer)
open powershell 
.\easy_ssh.ps1
You will be prompted to:

Pick an existing local user on the host or create a new one.

Enter / confirm the password (twice for “none”).

Choose the host’s Tailscale node from a list or type its 100.x.x.x address / DNS name.

When the wizard finishes you’ll see something like:

makefile
Copy
Edit
Created:
  host_setup_alice_100.99.42.17.ps1
  client_use_alice_100.99.42.17.ps1
  alice_100.99.42.17.rdp
3. Copy files to the host
Take host_setup_<user>_<ip>.ps1 to the target PC (USB, SMB share, whatever).

4. Run host setup as Administrator
powershell
Copy
Edit
# on the host PC
.\host_setup_alice_100.99.42.17.ps1
It will:

Install Tailscale if missing (silent /quiet installer).

Enable RDP, OpenSSH, membership in Administrators & Remote Desktop Users.

Start all services and bring Tailscale online.

⚠️ Reboot once after this step so the new groups / services are fully active.

5. Connect from a client
Option A — run the helper script:

powershell
Copy
Edit
# on any client machine with ssh & mstsc
.\client_use_alice_100.99.42.17.ps1
Pick “1 = SSH tunnel” to map your local 3389 → host 3389, then launch RDP.
Pick “2” for direct RDP over your tailnet.

Option B — just double-click the generated .rdp file.

🔐 Security notes & best practice
Passwords in files – the host-setup script embeds the password you typed.
Keep that file private or delete it after first run.

All scripts are idempotent: rerunning them is safe—existing users, services & firewall rules are detected and skipped.

Tailscale is installed from the official URL https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe.
If you prefer an internal mirror, edit the download URL before running.
