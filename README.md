# NeoTunnelssh.ps1

> **One-command PowerShell wizard that turns a fresh Windows PC into a securely reachable node—sets up admin user, RDP, OpenSSH, Tailscale & ready-made client scripts.**

---

## 🚀 Quick start

Prerequisites

🧠 At least 25 % brain capacity (you’ve got this)

run this in powershell

>**Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0; Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'**

🐕 Install Tailscale and sign in > **https://tailscale.com/download**


Quick Start

1. Grab the script

Download NeoTunnel.ps1 and drop it in any folder you like. Everything it generates will live next to it.

2. Run it on the host PC

.\NeoTunnel.ps1

The wizard will ask you to:

Choose or create a Windows user

Set/confirm the password (type none twice to stay with the same passwrod for windows )

Enter the host’s Tailscale IP (100.x.x.x) or tailnet DNS name

When it finishes you’ll see three shiny new files:

host_setup_<user>_<ip>.ps1     # one‑click host installer
client_use_<user>_<ip>.ps1     # helper script for your client
<user>_<ip>.rdp                # double‑click RDP shortcut

3. Copy the host installer

Move host_setup_<user>_<ip>.ps1 to the target PC (USB, SMB, pigeon…).

4. Run host setup as Administrator

# on the host PC
.\host_setup_<user>_<ip>.ps1

This script will silently:

Install Tailscale if missing (/quiet)

Enable RDP and OpenSSH

Add the user to Administrators & Remote Desktop Users

Start services and bring Tailscale online

Reboot once when it’s done so the new groups/services become active.

# 5. Connect from your client

Option A — use the helper
on any client with ssh & mstsc
.\client_use_<user>_<ip>.ps1

Choose:

1 → SSH tunnel (local 3389 → host 3389) and auto‑launch RDP

2 → Direct RDP over your tailnet

Option B — double‑click bliss

Open the generated .rdp file and log in.

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


🔐 Security notes & best practice
Passwords in files – the host-setup script embeds the password you typed.
Keep that file private or delete it after first run.

All scripts are idempotent: rerunning them is safe—existing users, services & firewall rules are detected and skipped.

Tailscale is installed from the official URL https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe.
If you prefer an internal mirror, edit the download URL before running.


**use taildrop to share files easily like the helper script just right click and send with tailscale**
