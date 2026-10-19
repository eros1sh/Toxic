#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Toxic kernel sürücüleri için test imzalama ortamını yapılandırır.

.DESCRIPTION
    Bu script Windows test imzalama modunu etkinleştirir ve geliştirme için
    gerekli araçları yapılandırır. YALNIZCA geliştirme makinelerinde çalıştırılmalı.
    Üretim sistemlerinde test imzalama ASLA etkinleştirilmemeli.

.NOTES
    Gereksinimler:
    - Yönetici PowerShell
    - Windows 11 22H2+
    - WDK 10.0.26100+ (makecert, signtool, inf2cat için)

    Çalıştırmak için:
    powershell -ExecutionPolicy Bypass -File scripts\setup-test-signing.ps1
#>

param(
    [switch]$DryRun,
    [string]$CertName = "ToxicTestCert",
    [string]$CertStore = "Cert:\LocalMachine\Root"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[>>] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!!] $Message" -ForegroundColor Yellow
}

# ── Ön Kontroller ──────────────────────────────────────────────────────────────

Write-Step "Sistem gereksinimleri kontrol ediliyor..."

# Hyper-V güvenlik özelliklerini kontrol et (HVCI/VBS ile uyumsuz)
$hvciEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue)?.EnableVirtualizationBasedSecurity

if ($hvciEnabled -eq 1) {
    Write-Warn "HVCI (Memory Integrity) etkin. Test sürücüleri yüklenemeyebilir."
    Write-Warn "Devre dışı bırakmak için: Windows Güvenlik > Cihaz Güvenliği > Çekirdek yalıtımı > Bellek bütünlüğü"
    Write-Warn "NOT: HVCI'yi kapatmak güvenlik açıkları oluşturabilir. Yalnızca VM kullanmanız önerilir."
    if (-not $DryRun) {
        $confirm = Read-Host "Devam etmek istiyor musunuz? (e/H)"
        if ($confirm -ne 'e' -and $confirm -ne 'E') {
            Write-Host "İptal edildi." -ForegroundColor Red
            exit 1
        }
    }
}

# WDK araçlarını bul
$wdkPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
)

$wdkBin = $null
foreach ($path in $wdkPaths) {
    if (Test-Path "$path\makecert.exe") {
        $wdkBin = $path
        break
    }
}

if (-not $wdkBin) {
    Write-Warn "WDK araçları bulunamadı. Önce WDK'yı yükleyin:"
    Write-Warn "https://learn.microsoft.com/tr-tr/windows-hardware/drivers/download-the-wdk"
    if (-not $DryRun) { exit 1 }
}
else {
    Write-Success "WDK bulundu: $wdkBin"
    $env:PATH = "$wdkBin;$env:PATH"
}

# ── Test Sertifikası Oluştur ───────────────────────────────────────────────────

Write-Step "Test sertifikası oluşturuluyor ($CertName)..."

$certExists = Get-ChildItem -Path $CertStore -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*$CertName*" }

if ($certExists) {
    Write-Warn "Sertifika zaten mevcut: $CertName. Atlanıyor."
}
elseif (-not $DryRun) {
    # Kendi imzalı test sertifikası oluştur
    & "$wdkBin\makecert.exe" `
        -r `
        -pe `
        -ss Root `
        -n "CN=$CertName" `
        -eku 1.3.6.1.5.5.7.3.3 `
        "$CertName.cer" 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[HATA] makecert başarısız oldu." -ForegroundColor Red
        exit 1
    }
    Write-Success "Sertifika oluşturuldu: $CertName.cer"
}
else {
    Write-Host "[DRY] makecert çalıştırılacak: -r -pe -ss Root -n CN=$CertName"
}

# ── Test İmzalama Modunu Etkinleştir ──────────────────────────────────────────

Write-Step "Test imzalama modu etkinleştiriliyor (bcdedit)..."

if (-not $DryRun) {
    & bcdedit /set testsigning on 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[HATA] bcdedit başarısız oldu." -ForegroundColor Red
        exit 1
    }
    Write-Success "Test imzalama etkinleştirildi."
}
else {
    Write-Host "[DRY] bcdedit /set testsigning on"
}

# Driver Signature Enforcement'ı geliştirme için devre dışı bırak
Write-Step "Kernel hata ayıklama seçenekleri yapılandırılıyor..."
if (-not $DryRun) {
    & bcdedit /set nointegritychecks on 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "nointegritychecks ayarlanamadı (opsiyonel)."
    }
    else {
        Write-Success "Bütünlük kontrolleri devre dışı bırakıldı (geliştirme modu)."
    }
}
else {
    Write-Host "[DRY] bcdedit /set nointegritychecks on"
}

# ── Araç Bilgisi ────────────────────────────────────────────────────────────────

Write-Step "Geliştirme ortamı özeti:"
Write-Host ""
Write-Host "  Sürücü imzalamak için:"
Write-Host "    signtool sign /v /s Root /n $CertName /t http://timestamp.digicert.com driver.sys"
Write-Host ""
Write-Host "  INF katalog dosyası oluşturmak için:"
Write-Host "    inf2cat /driver:.\driver /os:10_X64"
Write-Host ""
Write-Host "  Test imzalamayı kaldırmak için (üretim öncesi):"
Write-Host "    bcdedit /set testsigning off"
Write-Host "    bcdedit /deletevalue nointegritychecks"
Write-Host ""
Write-Warn "UYARI: Bu ayarlar yalnızca geliştirme VM'lerinde kullanılmalı."
Write-Warn "Değişikliklerin etkili olması için bilgisayarı yeniden başlatın."

# ── Tamamlandı ─────────────────────────────────────────────────────────────────

if (-not $DryRun) {
    $reboot = Read-Host "`nBilgisayarı şimdi yeniden başlatmak ister misiniz? (e/H)"
    if ($reboot -eq 'e' -or $reboot -eq 'E') {
        Write-Host "Yeniden başlatılıyor..." -ForegroundColor Yellow
        Restart-Computer -Force
    }
    else {
        Write-Host "`nDeğişikliklerin etkili olması için manuel olarak yeniden başlatın." -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[DRY RUN] Gerçek değişiklik yapılmadı." -ForegroundColor Yellow
}
