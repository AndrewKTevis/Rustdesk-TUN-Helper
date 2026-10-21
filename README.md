# Rustdesk Clash-TUN Helper

[简体中文](README.zh-CN.md)

A possible fix for RustDesk TCP direct connections when both PCs use Clash TUN.

[Download](https://github.com/AndrewKTevis/Rustdesk-TUN-Helper/releases)

## How to use

1. Download the single-file executable, run it on both PCs, and approve administrator access.
2. Right-click its icon in the system tray and select **Enable**.
3. After enabling it for the first time, restart RustDesk, then connect.

## Important

Enable **DNS override** in Clash Verge and set the DNS mode to **`redir-host`**.

Tested on both PCs with RustDesk **1.5.0+68** and Clash Verge **2.5.8**.

## Requirements

- Windows 10 / 11 x64
- .NET Framework 4.7.2 or later
- IPv4

## How it works

Monitors RustDesk destinations and adds temporary IPv4 routes through the physical adapter. Other apps using the same destination IP also use these routes. Routes expire within 20 seconds after an unexpected exit.

## Build

```powershell
.\scripts\bootstrap-dependencies.ps1
.\test.ps1
.\scripts\package.ps1
```

## License

[MIT](LICENSE).

---

This repository and application were primarily written by an AI agent.
