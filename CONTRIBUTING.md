# 开发约定

1. 修改 `src/Runtime.ps1` 或 `src/PatchEngine.cs`，不直接修改根目录生成文件。
2. 执行 `tools/Build.ps1` 更新单文件版本，执行 `tests/RunTests.ps1` 验证。
3. Windows PowerShell 5.1 需要 UTF-8 BOM 正确读取中文；构建器会为生成文件添加 BOM。含中文的 PowerShell 源码和测试文件也要保留 BOM。
4. 普通 CI 使用模拟数据，不安装驱动、不注册服务、不请求管理员权限。真实原版文件仅用于开发者本地的只读集成测试。
5. 不提交厂商二进制、驱动、配置、网卡 GUID、日志、用户目录、账户信息或打包的运行副本。
6. 支持新构建前应提交独立分析与测试依据，不能移除输入哈希或预期指令校验来“兼容”未知文件。

建议验证：

```powershell
.\tools\Build.ps1 -Check
.\tests\RunTests.ps1
# 可选：匹配版本的本地安装，只读验证。
.\tests\RunTests.ps1 -SourceDirectory 'C:\Program Files (x86)\UniVPN'
```

原有单实例实验和新编号实例的状态应准确区分；不要把离线补丁生成成功表述为多隧道连通已验证。
