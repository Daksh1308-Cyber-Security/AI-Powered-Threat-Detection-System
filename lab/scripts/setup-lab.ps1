#!/usr/bin/env python3
"""
setup-lab.ps1 - VirtualBox VM setup script (PowerShell)
AI-Powered Threat Detection System
Configures VirtualBox VMs for the security lab
"""

# This is a PowerShell script template.
# Copy the executable content below to setup-lab.ps1 and run as Administrator.

$ErrorActionPreference = "Stop"

# ===========================================
# LOCATE VIRTUALBOX
# ===========================================
# VirtualBox installs VBoxManage.exe without always adding it to PATH.
if (-not (Get-Command VBoxManage -ErrorAction SilentlyContinue)) {
    foreach ($candidate in @(
        "C:\Program Files\Oracle\VirtualBox",
        "C:\Program Files (x86)\Oracle\VirtualBox"
    )) {
        if (Test-Path "$candidate\VBoxManage.exe") {
            $env:Path = "$candidate;$env:Path"
            break
        }
    }
}

# ===========================================
# CONFIGURATION
# ===========================================
$LAB_DIR = "C:\Users\DAX\Desktop\projects\TOP3 CYBER PROJECT\AI-Powered Threat Detection System\lab\VMs"
$HOST_ONLY_NETWORK = "vboxnet0"

$KALI_NAME = "Kali-Attacker"
$KALI_IP = "192.168.56.10"
$KALI_ISO = "C:\ISOs\kali-linux-2024.4-installer-amd64.iso"

$UBUNTU_NAME = "Ubuntu-Target"
$UBUNTU_IP = "192.168.56.20"
$UBUNTU_ISO = "C:\ISOs\ubuntu-22.04.4-desktop-amd64.iso"

$WINDOWS_NAME = "Windows-Target"
$WINDOWS_IP = "192.168.56.30"
$WINDOWS_ISO = "C:\ISOs\Win10_22H2_English_x64.iso"

# ===========================================
# HELPER FUNCTIONS
# ===========================================
function Show-Banner {
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  AI-Powered Threat Detection System - Lab Setup"          -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-VirtualBox {
    try {
        $version = vboxmanage --version
        Write-Host "[+] VirtualBox detected: $version" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] VirtualBox not found. Please install VirtualBox 7.0+" -ForegroundColor Red
        return $false
    }
}

function Resolve-HostOnlyNetwork {
    # VBox 7 names adapters "VirtualBox Host-Only Ethernet Adapter", not "vboxnet0".
    # Reuse an existing 192.168.56.x adapter or create one.
    $name = $null
    $current = $null
    foreach ($line in (vboxmanage list hostonlyifs)) {
        if ($line -match '^Name:\s*(.*)') { $current = $Matches[1] }
        elseif ($line -match '^IPAddress:\s*(.*)') {
            if ($Matches[1] -like '192.168.56.*') { $name = $current; break }
        }
    }
    if ($name) {
        Write-Host "[+] Using existing host-only network: $name" -ForegroundColor Green
    } else {
        vboxmanage hostonlyif create | Out-Null
        $name = (vboxmanage list hostonlyifs | Select-String '^Name:').Value | Select-Object -Last 1
        $name = $name -replace '^Name:\s*', ''
        try {
            vboxmanage hostonlyif ipconfig $name --ip 192.168.56.1 --netmask 255.255.255.0
            Write-Host "[+] Host-only network created: $name (192.168.56.1/24)" -ForegroundColor Green
        } catch {
            Write-Host "[-] Could not set adapter IP - rerun as Administrator: $_" -ForegroundColor Red
        }
    }
    return $name
}

function Test-IsoFiles {
    param([string[]]$IsoPaths)
    $missing = $IsoPaths | Where-Object { -not (Test-Path $_) }
    if ($missing) {
        Write-Host "[-] Missing ISO images:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        Write-Host "    Download the images above and place them, or edit the paths at the top of this script." -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Create-VM {
    param(
        [string]$Name,
        [int]$Cpu,
        [int]$Ram,
        [int]$Disk,
        [string]$Iso
    )
    
    Write-Host "[*] Creating VM: $Name" -ForegroundColor Yellow
    
    $VMPath = "$LAB_DIR\$Name"
    
    # Create VM
    vboxmanage createvm --name $Name --basefolder $VMPath --ostype Ubuntu_64 --register
    
    # Configure VM
    vboxmanage modifyvm $Name --cpus $Cpu --memory $Ram --vram 128
    vboxmanage modifyvm $Name --nic1 hostonly --hostonlyadapter1 $HOST_ONLY_NETWORK
    vboxmanage modifyvm $Name --ioapic on --audio none
    
    # Create disk
    vboxmanage createmedium disk --filename "$VMPath\$Name.vdi" --size $Disk --format VDI
    
    # Attach disk and ISO
    vboxmanage storagectl $Name --name "SATA" --add sata --controller IntelAhci
    vboxmanage storageattach $Name --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$VMPath\$Name.vdi"
    vboxmanage storageattach $Name --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium $Iso
    
    # Boot order
    vboxmanage modifyvm $Name --boot1 dvd --boot2 disk
    
    Write-Host "[+] VM created: $Name" -ForegroundColor Green
}

function Configure-Network {
    param(
        [string]$Name,
        [string]$IpAddress
    )
    Write-Host "[*] Configuring network for $Name..." -ForegroundColor Yellow
    Write-Host "[+] Set static IP: $IpAddress"
}

function Main {
    Show-Banner
    
    # Check VirtualBox
    if (-not (Test-VirtualBox)) { exit 1 }
    
    # Check ISO images before creating anything
    if (-not (Test-IsoFiles @($KALI_ISO, $UBUNTU_ISO, $WINDOWS_ISO))) { exit 1 }
    
    # Create lab directory
    New-Item -ItemType Directory -Path $LAB_DIR -Force | Out-Null
    
    # Resolve host-only network (192.168.56.0/24)
    $script:HOST_ONLY_NETWORK = Resolve-HostOnlyNetwork
    if (-not $script:HOST_ONLY_NETWORK) {
        Write-Host "[-] No host-only network available. Rerun as Administrator." -ForegroundColor Red
        exit 1
    }
    
    # Create VMs
    Write-Host ""
    Write-Host "[*] Creating lab VMs..." -ForegroundColor Yellow
    
    Create-VM -Name $KALI_NAME -Cpu 2 -Ram 4096 -Disk 50000 -Iso $KALI_ISO
    Configure-Network -Name $KALI_NAME -IpAddress $KALI_IP
    
    Create-VM -Name $UBUNTU_NAME -Cpu 4 -Ram 8192 -Disk 100000 -Iso $UBUNTU_ISO
    Configure-Network -Name $UBUNTU_NAME -IpAddress $UBUNTU_IP
    
    Create-VM -Name $WINDOWS_NAME -Cpu 4 -Ram 8192 -Disk 80000 -Iso $WINDOWS_ISO
    Configure-Network -Name $WINDOWS_NAME -IpAddress $WINDOWS_IP
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  Lab Setup Complete!"                                    -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Start each VM and complete OS installation"
    Write-Host "  2. Configure static IPs:"
    Write-Host "     - Kali:     $KALI_IP"
    Write-Host "     - Ubuntu:   $UBUNTU_IP"
    Write-Host "     - Windows:  $WINDOWS_IP"
    Write-Host "  3. Run lab/scripts/generate-attack-traffic.py from Kali"
    Write-Host ""
}

# Run setup
Main