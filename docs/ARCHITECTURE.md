# Architecture

| Module | Contents |
| --- | --- |
| `src/App` | Tray, windows, privileges, control pipe |
| `src/Core` | Process validation, ETW, route lifecycle |
| `src/Networking` | Adapters, DNS, TCP table, route APIs |
| `tests` | Regression tests and native checks |

| Setting | Value |
| --- | --- |
| Route lifetime | 20 seconds |
| Renewal | 3 seconds |
| Idle timeout | 5 minutes |
| Target limit | 128 |
| Logs | 512 KiB × 2 |

```powershell
& '.\Rustdesk Clash-TUN Helper.exe' --command status
& '.\Rustdesk Clash-TUN Helper.exe' --command enable
& '.\Rustdesk Clash-TUN Helper.exe' --command disable
& '.\Rustdesk Clash-TUN Helper.exe' --command quit
```
