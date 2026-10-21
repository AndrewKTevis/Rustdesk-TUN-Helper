# Rustdesk Clash-TUN Helper

[English](README.md)

两台电脑都开启 Clash TUN（虚拟网卡代理）时，RustDesk TCP 直连的一种可能方案。

[下载](https://github.com/AndrewKTevis/Rustdesk-TUN-Helper/releases)

## 使用方法

1. 下载单文件可执行程序，在两台电脑上运行并同意管理员权限。
2. 在系统托盘中右键点击程序图标，选择 **Enable**。
3. 首次启用后，重启 RustDesk，再建立连接。

## 特别提醒

请在 Clash Verge 中开启 **DNS 覆写**，将 DNS 模式设为 **`redir-host`**。

两端测试版本一致：RustDesk **1.5.0+68**、Clash Verge **2.5.8**。

## 环境

- Windows 10 / 11 x64
- .NET Framework 4.7.2 或更高版本
- IPv4

## 大致工作方式

监测 RustDesk 的目标地址，为这些公网 IPv4 地址添加经物理网卡的临时路由。同目标 IP 的其他应用也会使用这些路由。程序异常退出后，路由在 20 秒内到期。

## 构建

```powershell
.\scripts\bootstrap-dependencies.ps1
.\test.ps1
.\scripts\package.ps1
```

## 许可

[MIT](LICENSE)。

---

本仓库及程序主要由 AI Agent 编写。
