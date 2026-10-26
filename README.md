# UniVPN Multi

Windows 下的 UniVPN 原生多实例实验脚本。把一个脚本放到官方客户端根目录，每次运行自动新增一张 TAP 网卡，并生成下一套 `UniVPN2`、`UniVPN3`……客户端。

<img width="1239" height="721" alt="image" src="https://github.com/user-attachments/assets/a538e431-7995-4666-9718-28130ecb4512" />


**目前只支持 UniVPN `10781.19.0.1214` 的指定构建。** 相同版本号不代表文件相同；脚本会校验三个 EXE 的 SHA256，不匹配即停止。项目不包含厂商程序、驱动、账号或 VPN 配置。

官方客户端的版本与下载入口：[联软 UniVPN 下载页面](https://www.leagsoft.com/doc/article/103107.html)。请安装上述受支持构建；下载页面中的其他版本不保证兼容。

如需为另一个**精确构建**重新分析和生成 profile，可参考 [`skills/univpn-multi-adapter`](skills/univpn-multi-adapter/SKILL.md)。该流程只做逐构建验证，不能把版本号或哈希校验放宽成通用兼容。

## 安装与使用

1. 下载仓库根目录的 **`UniVPN-Multi.ps1`**，放到官方安装目录，与 `UniVPN.exe` 放在一起。使用整个仓库时，仍然只需复制这一个文件。
2. 断开 VPN，并从系统托盘**彻底退出原版和所有副本**。只关闭窗口可能仍在后台运行。
3. 执行
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\UniVPN-Multi.ps1
   ```
5. 等待生成并打开新的客户端，然后手动添加网关、登录。

<img width="1743" height="1239" alt="e7560894-799e-44fb-87f5-9e2a903fa359" src="https://github.com/user-attachments/assets/489d8b4d-5ccb-45dc-859a-6994b1c92286" />


如果系统提示脚本未进行数字签名，可在官方安装目录的 PowerShell 窗口中执行以下命令；执行策略仅对本次启动生效：



检测到原版、任一副本、连接后台或已启用的 TAP 连接时，会弹窗提示退出并停止，**不会自动关闭客户端**。官方常驻服务无需手动停止。

默认安装时的文件结构：

```text
C:\Program Files (x86)\
├─ UniVPN\
│  ├─ UniVPN.exe
│  ├─ UniVPN-Multi.ps1       每次运行新增一套
│  └─ .univpn-multi\        实例记录、目录联接和驱动安装日志
├─ UniVPN2\
│  └─ Open-UniVPN2.cmd       以后打开同一实例，用这个
└─ UniVPN3\
   └─ Open-UniVPN3.cmd
```

**打开已有实例**：双击对应目录里的 `Open-UniVPN编号.cmd`，不新增网卡，允许与其他客户端同时运行。已有窗口隐藏时，从托盘打开。

不要移动原脚本、重命名实例目录或删除 `.univpn-multi`，生成的启动入口和服务会依赖这些位置。原版安装文件不会被修改；原版用户的账号密码不会复制到副本。新增服务为手动启动，不设置开机自动连接。

## 卸载

以下以卸载自动生成的 `UniVPN2` 为例；第 3 实例对应 `UniVPN3`、`UVP003Service`、`UVP003`，以此类推。

1. 在目标副本中断开 VPN，并从系统托盘彻底退出。
2. 在开始菜单找到 PowerShell，右键选择**“以管理员身份运行”**。先检查服务的实际路径：

   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='UVP002Service'" |
       Select-Object Name, State, PathName
   ```

   确认路径指向原安装目录下的 `.univpn-multi\UVP002\promote\UVP002PromoteService.exe` 后，停止并删除该服务：

   ```powershell
   Stop-Service -Name UVP002Service
   sc.exe delete UVP002Service
   ```

3. 等待服务删除、相关进程退出后，在资源管理器中删除副本目录，例如 `C:\Program Files (x86)\UniVPN2`。若不再保留登录配置，可删除 `%APPDATA%\UVP002`。
4. 如需移除专用网卡，先退出**所有 UniVPN 客户端**。查看原安装目录 `.univpn-multi\instance-002.json` 的 `TapGuid`，核对目标网卡后再通过设备管理器卸载。删除 TAP 可能影响共享驱动；无法确认归属时先保留网卡。不要执行 `tapinstall remove tap0901`，它会匹配多张网卡。

**不要删除原版的 `UniVPNService`，也不要使用官方卸载程序移除副本**，以免影响原版和共享组件。早期手工创建的 `UniVP2` 使用 `UniVP2Service`，与自动生成的 `UniVPN2` 不同，操作前务必核对实际路径。

`.univpn-multi` 中的实例 JSON 可保留作记录和编号占位；不要删除整个目录，其中可能仍有其他实例依赖的目录联接。更多细节见[维护与移除说明](docs/MAINTENANCE.md)。

## 要求和当前验证范围

- Windows、Windows PowerShell 5.1 或 PowerShell 7，安装了匹配构建的官方 UniVPN。
- 创建网卡、注册服务和启动服务需要管理员权限，脚本会通过 UAC 提权。请使用同一用户，不要切换到另一个管理员账户。
- 无需 Python、pip、网络下载或额外 PowerShell 模块。
- 已验证早期第二实例的界面和后台可并存；自动编号版完成离线二进制生成检查。**自动安装的完整流程和多条隧道的业务连通仍需实际验证。**
- 新增 TAP 涉及共享驱动，所以创建实例前必须退出所有客户端。内网网段、系统路由和 DNS 仍由 Windows 共享；程序多开不代表所有网关策略都兼容。
- 编号支持 2–999，仅为编号范围，不代表能运行同等数量的 VPN。已有的早期 `UniVP2` 实验实例也会被识别，不覆盖。

## 出错时

错误显示在控制台；如已进入创建阶段，实例状态和驱动日志保存在 `.univpn-multi`。失败的编号会保留，不会复用或覆盖。

脚本不做全量自动回滚，可能留下已创建的网卡、目录或停止的服务。不会自动卸载 TAP，以免再次重载共享驱动。先查看错误，再处理残留，避免反复执行后不断新增网卡。

查看[维护与移除说明](docs/MAINTENANCE.md)和[实现与兼容性说明](docs/ARCHITECTURE.md)。不要用官方客户端的卸载程序移除某个副本，它可能操作原版的公共组件。

## 开发与验证

维护 `src/Runtime.ps1` 和 `src/PatchEngine.cs`，然后生成根目录的单文件脚本。不要手动编辑生成文件。

```powershell
.\tools\Build.ps1
.\tools\Build.ps1 -Check
.\tests\RunTests.ps1
```

普通测试不需要安装 UniVPN，也不会操作实际服务、进程或网卡。GitHub Actions 在 Windows PowerShell 5.1 和 PowerShell 7 中运行这些检查。

在安装了匹配客户端的本机，还可以执行只读集成检查：

```powershell
.\tests\RunTests.ps1 -SourceDirectory 'C:\Program Files (x86)\UniVPN'
```

该检查只读取原文件并在内存中生成多个编号的补丁，不新增网卡、注册服务或登录 VPN。

## 许可证

本项目自有脚本和源码使用 [MIT License](LICENSE)。厂商 UniVPN、驱动及其组件不包含在仓库中，也不适用本项目许可证。本项目为独立实验，与联软没有隶属关系。
