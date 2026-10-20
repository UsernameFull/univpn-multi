# 维护与移除

## 再次打开窗口

使用副本目录中的 `Open-UniVPN编号.cmd`。它请求管理员权限后打开同一实例，不新增网卡。原始 `UniVPN-Multi.ps1` 不带参数运行则会新增一套，不能当作普通启动器反复使用。

## 移除自动生成实例的服务

先在目标副本中断开 VPN 并从托盘退出。打开**管理员 PowerShell**。以第 2 实例为例，先确认路径，再停止并删除独立服务：

```powershell
Get-CimInstance Win32_Service -Filter "Name='UVP002Service'" |
    Select-Object Name, State, PathName
```

确认它指向原目录 `.univpn-multi\UVP002\promote\UVP002PromoteService.exe`，随后执行：

```powershell
Stop-Service -Name UVP002Service
sc.exe delete UVP002Service
```

第 3 实例对应 `UVP003Service`，以此类推。不要操作 `UniVPNService`，它属于原版。早期手工实验版名为 `UniVP2Service`，并非自动版 `UVP002Service`；移除前以实际服务路径确认。

如果提示需要管理员权限，在开始菜单中找到 PowerShell，右键“以管理员身份运行”。单纯换到脚本所在目录不能获得管理员权限。

## 文件、配置与网卡

服务删除、相关进程全部结束后，可在资源管理器中删除对应的 `UniVPN编号` 程序目录。用户配置位于 `%APPDATA%\UVP编号`，例如 `%APPDATA%\UVP002`，可按是否保留配置决定删除。

`.univpn-multi\UVP编号` 是目录联接，操作前应确认它指向哪一个副本；不要对整个原安装目录使用递归删除命令。实例 JSON 可保留用于审计和编号占位，之后创建会继续递增。

网卡 GUID 记录在 `.univpn-multi\instance-编号.json` 的 `TapGuid` 字段。若要删除网卡，应先退出全部 VPN，并在设备管理器中核对目标设备；删除 TAP 可能再次影响共享驱动。不要执行 `tapinstall remove tap0901`，它会匹配多张网卡。

不确定某张网卡归属时保留它。移除服务和程序后，剩余的断开网卡不会自动建立 VPN 连接。

## 提交问题

报告问题时说明 Windows / PowerShell 版本、UniVPN 文件是否通过哈希检查、错误阶段及脱敏后的错误文本。不要直接提交 `.univpn-multi`、厂商二进制、完整日志、网关地址、账号密码或用户配置。仓库忽略规则已排除这些本地产物。
