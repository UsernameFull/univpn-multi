#requires -Version 5.1
<#
.SYNOPSIS
Create an additional native UniVPN instance beside the original installation.
.DESCRIPTION
Place the generated script next to UniVPN.exe and run it. Existing clients must
be fully exited. Each invocation creates one TAP adapter and one isolated copy.
Only the documented binary build is supported; VPN authentication is manual.
.PARAMETER OpenInstance
Reopen a previously generated instance without creating an adapter.
.PARAMETER SelfTest
Check supported original binaries and generate patches in memory only.
.PARAMETER SourceDirectory
Override the original installation directory. Defaults to the script directory.
#>
[CmdletBinding()]
param(
    [int]$OpenInstance = 0,
    [switch]$SelfTest,
    [string]$SourceDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Windows PowerShell 5.1 -File can evaluate parameter defaults before
# $PSScriptRoot is populated. Resolve the default in the script body instead.
if(-not $PSBoundParameters.ContainsKey('SourceDirectory')){$SourceDirectory=$PSScriptRoot}
$source=[IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
$scriptFile=$PSCommandPath
$parent=[IO.Path]::GetDirectoryName($source)
$stateRoot=Join-Path $source '.univpn-multi'
$sourceFiles=@('UniVPN.exe','promote\UniVPNPromoteService.exe','serviceclient\UniVPNCS.exe')

function Is-Administrator {
    $p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-TapAdapters {
    @(Get-NetAdapter -IncludeHidden | Where-Object {$_.InterfaceDescription -like 'TAP-Windows Adapter V9*'})
}
function Assert-NoRunningClients {
    # Services are deliberately excluded: the official service normally stays
    # running after its UI exits. Check UIs and connection backends, including
    # the earlier manual UniVP2 experiment and all generated UVP### instances.
    $clients=@(Get-Process | Where-Object {$_.ProcessName -match '^(UniVPN|UniVP2|UVP\d{3})(CS)?$'})
    $activeTaps=@(Get-TapAdapters | Where-Object {$_.Status -eq 'Up'})
    if($clients.Count -or $activeTaps.Count){
        $exception=[InvalidOperationException]::new('当前已有 VPN 在运行。请先断开 VPN，并从托盘彻底退出所有 UniVPN 客户端（包括副本），然后重新执行脚本。仅关闭窗口可能仍在后台运行；刚退出时请稍等几秒再试。')
        $exception.Data['VpnRunning']=$true
        throw $exception
    }
}
function Get-InstanceInfo([int]$Number) {
    if($Number -lt 2 -or $Number -gt 999){throw 'Supported instance numbers: 2 through 999.'}
    $product='UVP{0:D3}' -f $Number
    [pscustomobject]@{
        Number=$Number; Product=$product; Service=$product+'Service'
        Directory=(Join-Path $parent "UniVPN$Number")
        Alias=(Join-Path $stateRoot $product)
        Record=(Join-Path $stateRoot ('instance-{0:D3}.json' -f $Number))
        RpcPort=29190+$Number-1; BackendPort=19060+$Number-1
    }
}
function Get-NextNumber {
    $numbers=@(1)
    foreach($item in @(Get-ChildItem -LiteralPath $parent -Directory)){
        if($item.Name -match '^UniVPN(\d+)$'){$numbers+=[int]$Matches[1]}
        if($item.Name -eq 'UniVP2'){$numbers+=2} # Keep the existing manual experiment.
    }
    if(Test-Path -LiteralPath $stateRoot){
        foreach($item in @(Get-ChildItem -LiteralPath $stateRoot -Filter 'instance-*.json' -File)){
            if($item.Name -match '^instance-(\d+)\.json$'){$numbers+=[int]$Matches[1]}
        }
    }
    foreach($service in @(Get-CimInstance Win32_Service)){
        if($service.Name -match '^UVP(\d{3})Service$'){$numbers+=[int]$Matches[1]}
        if($service.Name -eq 'UniVP2Service'){$numbers+=2}
    }
    return [int](($numbers | Measure-Object -Maximum).Maximum+1)
}
function Get-Images($Info,[string]$Guid) {
    for($kind=0;$kind -lt 3;$kind++){
        $bytes=[IO.File]::ReadAllBytes((Join-Path $source $sourceFiles[$kind]))
        $patched=[UniVpnMulti.BinaryPatch]::PatchInstance($bytes,$kind,$Guid,$Info.Number)
        $target=$sourceFiles[$kind].Replace('UniVPN',$Info.Product)
        [pscustomobject]@{Target=$target;Bytes=$patched;Hash=[UniVpnMulti.BinaryPatch]::Hash($patched)}
    }
}
function Save-Record($Info,$Record) {
    $Record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Info.Record -Encoding UTF8
}
function Assert-ServiceOwner($Info) {
    $svc=Get-CimInstance Win32_Service -Filter "Name='$($Info.Service)'"
    if(-not $svc){throw 'Instance service is missing.'}
    $binary='"'+(Join-Path $Info.Alias ('promote\'+$Info.Product+'PromoteService.exe'))+'"'
    if($svc.PathName -cne $binary){throw 'Service path does not match this instance.'}
    return $svc
}
function Open-Client($Info,$Record) {
    if($Record.Status -ne 'Ready'){throw 'This instance is incomplete; inspect its log before using it.'}
    $tap=@(Get-TapAdapters | Where-Object {([guid]$_.InterfaceGuid) -eq ([guid]$Record.TapGuid)})
    if($tap.Count -ne 1){throw 'The instance TAP adapter is missing.'}
    $aliasItem=Get-Item -LiteralPath $Info.Alias -Force
    if($aliasItem.LinkType -ne 'Junction' -or @($aliasItem.Target).Count -ne 1 -or
        [IO.Path]::GetFullPath([string]$aliasItem.Target).TrimEnd('\') -ine $Info.Directory){throw 'Instance directory link mismatch.'}
    foreach($image in @(Get-Images $Info $Record.TapGuid)){
        if((Get-FileHash -LiteralPath (Join-Path $Info.Directory $image.Target)).Hash -ne $image.Hash){throw 'Instance binary verification failed.'}
    }
    $svc=Assert-ServiceOwner $Info
    if($svc.State -ne 'Running'){
        if(Get-NetTCPConnection -State Listen -LocalPort $Info.RpcPort -ErrorAction SilentlyContinue){throw 'RPC port is occupied.'}
        Start-Service $Info.Service
    }
    $svc=Assert-ServiceOwner $Info
    $deadline=(Get-Date).AddSeconds(10)
    do{
        $listeners=@(Get-NetTCPConnection -State Listen -LocalPort $Info.RpcPort -ErrorAction SilentlyContinue)
        if($listeners.Count){break}
        Start-Sleep -Milliseconds 250
    }while((Get-Date) -lt $deadline)
    if($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne $svc.ProcessId -or $listeners[0].LocalAddress -ne '127.0.0.1'){throw 'RPC listener verification failed.'}
    $profileDir=Join-Path ([Environment]::GetFolderPath('ApplicationData')) $Info.Product
    $null=New-Item -ItemType Directory -Path (Join-Path $profileDir 'config') -Force
    if(-not(Test-Path -LiteralPath (Join-Path $profileDir 'sysconfig.ini'))){
        Copy-Item -LiteralPath (Join-Path $Info.Directory 'sysconfig.ini') -Destination $profileDir
    }
    $running=@(Get-Process -Name $Info.Product -ErrorAction SilentlyContinue)
    if(-not $running.Count){Start-Process -FilePath (Join-Path $Info.Alias ($Info.Product+'.exe')) -WorkingDirectory $Info.Alias}
    Write-Host ("Opened UniVPN{0}. Login manually. Existing hidden windows are available in the tray." -f $Info.Number) -ForegroundColor Green
}

if (-not ('UniVpnMulti.BinaryPatch' -as [type])) {
Add-Type -TypeDefinition @'
// Binary patch profile for UniVPN 10781.19.0.1214.
// Only byte-identical supported inputs are accepted. No vendor binary is bundled.
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace UniVpnMulti {
 public static class BinaryPatch {
  static readonly Encoding Latin = Encoding.GetEncoding(28591);
  public static string Hash(byte[] b) {
   using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(b)).Replace("-","").ToLowerInvariant();
  }
  static uint U32(byte[] b,int o) {return BitConverter.ToUInt32(b,o);}
  static void Put(byte[] b,int o,uint v) {Array.Copy(BitConverter.GetBytes(v),0,b,o,4);}
  static int Pe(byte[] b) {
   if(b.Length<64 || b[0]!=77 || b[1]!=90) throw new Exception("Not a PE file");
   int p=checked((int)U32(b,60));
   if(U32(b,p)!=0x4550) throw new Exception("Invalid PE signature");
   return p;
  }
  static ulong Base(byte[] b) {int p=Pe(b)+24; return BitConverter.ToUInt16(b,p)==0x20b ? BitConverter.ToUInt64(b,p+24) : U32(b,p+28);}
  static int Sections(byte[] b) {int p=Pe(b);return p+24+BitConverter.ToUInt16(b,p+20);}
  static int Offset(byte[] b,uint va) {
   ulong r=(ulong)va-Base(b); int p=Pe(b), s=Sections(b);
   for(int i=0;i<BitConverter.ToUInt16(b,p+6);i++,s+=40) {
    uint start=U32(b,s+12), size=U32(b,s+16);
    if(r>=start && r<start+size) return checked((int)(U32(b,s+20)+r-start));
   }
   throw new Exception("Address outside mapped sections");
  }
  static void Word(byte[] b,int offset,uint before,uint after) {
   if(U32(b,offset)!=before) throw new Exception("Unexpected bytes at "+offset.ToString("x"));
   Put(b,offset,after);
  }
  static byte[] Names(byte[] b) {
   string all=Latin.GetString(b);
   foreach(var enc in new[]{Encoding.ASCII,Encoding.Unicode}) {
    string[] old={"UniVPN","Univpn","Global\\SVN"};
    string[] next={"UniVP2","Univp2","Global\\TVN"};
    for(int i=0;i<old.Length;i++) all=all.Replace(Latin.GetString(enc.GetBytes(old[i])),Latin.GetString(enc.GetBytes(next[i])));
   }
   return Latin.GetBytes(all);
  }
  static uint Payload(byte[] b,string guid) {
   int p=Pe(b),s=Sections(b);
   byte[] payload=Encoding.ASCII.GetBytes(guid.ToUpperInvariant()+"\0"+guid.ToLowerInvariant()+"\0");
   for(int i=0;i<BitConverter.ToUInt16(b,p+6);i++,s+=40) {
    if(Encoding.ASCII.GetString(b,s,8).TrimEnd('\0')!=".rdata") continue;
    uint used=U32(b,s+8),size=U32(b,s+16); int offset=checked((int)(U32(b,s+20)+used));
    if(size<used+payload.Length) throw new Exception("Insufficient .rdata padding");
    for(int n=0;n<payload.Length;n++) if(b[offset+n]!=0) throw new Exception("Padding is not empty");
    Array.Copy(payload,0,b,offset,payload.Length); Put(b,s+8,used+(uint)payload.Length);
    return checked((uint)(Base(b)+U32(b,s+12)+used));
   }
   throw new Exception("No .rdata section");
  }
  static void Pointer(byte[] b,uint va,uint before,uint after,bool x64) {
   int offset=Offset(b,va);
   if(x64) {
    if(b[offset]!=0x48 || b[offset+1]!=0x8d || b[offset+2]!=0x15) throw new Exception("Expected LEA RDX instruction");
    Word(b,offset+3,unchecked(before-va-7),unchecked(after-va-7));
   } else {
    if(b[offset]!=0xc7 || b[offset+1]!=0x44 || b[offset+2]!=0x24 || b[offset+3]!=4) {
     if(b[offset]!=0xc7 || b[offset+1]!=0x04 || b[offset+2]!=0x24) {
      if(b[offset]!=0xc7 || b[offset+1]!=0x44 || b[offset+2]!=0x24 || b[offset+3]!=8) throw new Exception("Expected MOV instruction");
     }
    }
    int immediate=b[offset+1]==0x04 ? 3 : 4;
    Word(b,offset+immediate,before,after);
   }
  }
  public static byte[] Patch(byte[] original,int kind,string guid) {
   string[] sourceHashes={
    "24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1",
    "e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10",
    "cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39"};
   string[] intermediate={
    "56e6b9b4562ba959ba493b1c7e7f858aefdc1b97a980ddf8c6597f1ec7907e5b",
    "54f44a7c4d740a31b70b7f0a6496792703f4ed107e91e41e823bb3ec48f0781e",
    "e8b4542b61468577032adbf75a16d776c9a213c2cc022f4f620fd986e33ee892"};
   if(Hash(original)!=sourceHashes[kind]) throw new Exception("Unsupported UniVPN binary/version. No patch applied.");
   byte[] b=Names(original);
   int[] ports={0xb0962,0x12f9f,0x49c96};
   uint oldPort=kind==2 ? 19060U : 29190U;
   Word(b,ports[kind],oldPort,oldPort+1);
   if(Hash(b)!=intermediate[kind]) throw new Exception("Intermediate patch hash mismatch");
   if(kind==1) return b;
   uint upper=Payload(b,guid),lower=upper+(uint)guid.Length+1;
   if(kind==0) {
    Pointer(b,0x41b143,0x5b334e,0x64cd7b,false);
    Pointer(b,0x4b3920,0x64cd59,0x64cd7b,false);
    Pointer(b,0x41b1c3,0x5b335a,upper,false);
    Pointer(b,0x4b39a2,0x64cd65,lower,false);
   } else {
    Pointer(b,0x4b3843,0x5fddf0,0x5fb7ef,true);
    Pointer(b,0x4b412e,0x5fb7cd,0x5fb7ef,true);
    Pointer(b,0x4b7b8e,0x5fddf0,0x5fb7ef,true);
    Pointer(b,0x4b387e,0x5fc766,upper,true);
    Pointer(b,0x4b41b5,0x5fb7d9,lower,true);
    Pointer(b,0x4b7bc9,0x5fc766,upper,true);
   }
   return b;
  }

  public static byte[] PatchInstance(byte[] original,int kind,string guid,int number) {
   if(number<2 || number>999) throw new Exception("Instance number out of range");
   guid=new Guid(guid).ToString("B").ToUpperInvariant();
   byte[] b=Patch(original,kind,guid);
   string product="UVP"+number.ToString("D3");
   string all=Latin.GetString(b);
   foreach(var enc in new[]{Encoding.ASCII,Encoding.Unicode}) {
    string[] old={"UniVP2","Univp2","Global\\TVN"};
    string[] next={product,product,"Global\\"+number.ToString("D3")};
    for(int i=0;i<old.Length;i++) all=all.Replace(Latin.GetString(enc.GetBytes(old[i])),Latin.GetString(enc.GetBytes(next[i])));
   }
   b=Latin.GetBytes(all);
   int[] ports={0xb0962,0x12f9f,0x49c96};
   uint originalPort=kind==2 ? 19060U : 29190U;
   Word(b,ports[kind],originalPort+1,originalPort+(uint)number-1);
   return b;
  }

 }
}
'@
}

$held=$false
$mutex=$null
$info=$null
$record=$null
try {
    # Verify every original executable before elevation or any system change.
    $null=@(Get-Images (Get-InstanceInfo 2) '{00000000-0000-0000-0000-000000000000}')
    if($SelfTest){
        $fixture='{11111111-2222-3333-4444-555555555555}'
        $hashes=@{}
        foreach($n in @(2,3,10,999)){
            $testInfo=Get-InstanceInfo $n
            $testImages=@(Get-Images $testInfo $fixture)
            if($testImages.Count -ne 3){throw 'Image count mismatch'}
            foreach($image in $testImages){
                if($hashes.ContainsKey($image.Hash)){throw 'Instances unexpectedly share a binary hash'}
                $hashes[$image.Hash]=$true
            }
            Write-Output ("PASS build #{0}: {1}, ports {2}/{3}, 3 independent binaries" -f $n,$testInfo.Product,$testInfo.RpcPort,$testInfo.BackendPort)
        }
        Write-Output ("Next available instance on this computer: {0}" -f (Get-NextNumber))
        Write-Output 'Self-test changed no services, adapters, or client files.'
        return
    }
    if(-not $OpenInstance){Assert-NoRunningClients}
    if(-not(Is-Administrator)){
        $escapedScript=$scriptFile.Replace("'","''")
        $escapedSource=$source.Replace("'","''")
        $command="& '$escapedScript' -SourceDirectory '$escapedSource' -OpenInstance $OpenInstance"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $process=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Verb RunAs -PassThru -Wait
        if($process.ExitCode -ne 0){throw 'Elevated action did not complete. See the log in .univpn-multi.'}
        return
    }
    $mutex=[Threading.Mutex]::new($false,'Global\UniVPNMultiInstaller10781')
    try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
    if(-not $held){throw 'Another instance creation is already in progress.'}
    if($OpenInstance){
        $info=Get-InstanceInfo $OpenInstance
        $record=Get-Content -LiteralPath $info.Record -Raw | ConvertFrom-Json
        Open-Client $info $record
        return
    }
    Assert-NoRunningClients
    $info=Get-InstanceInfo (Get-NextNumber)
    if((Test-Path -LiteralPath $info.Directory) -or (Test-Path -LiteralPath $info.Alias) -or (Get-Service $info.Service -ErrorAction SilentlyContinue)){
        throw 'Instance destination is occupied; nothing was overwritten.'
    }
    foreach($port in @($info.RpcPort,$info.BackendPort)){
        if(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue){throw "Port $port is already occupied. No adapter has been added."}
    }
    $null=New-Item -ItemType Directory -Path $stateRoot -Force
    $record=[ordered]@{
        Number=$info.Number;Product=$info.Product;Directory=$info.Directory;Alias=$info.Alias
        Service=$info.Service;RpcPort=$info.RpcPort;BackendPort=$info.BackendPort
        Status='Creating';TapGuid=$null;CreatedAt=(Get-Date).ToString('o');Error=$null
    }
    Save-Record $info $record
    Write-Host ("Creating UniVPN{0} -> {1}" -f $info.Number,$info.Directory)
    # Recheck immediately before the driver action, including a client started
    # during copying/elevation. Never stop or disconnect other clients here.
    Assert-NoRunningClients
    Write-Host 'All VPN clients are closed. Adding a dedicated TAP adapter.'
    $before=@(Get-TapAdapters)
    $driver=Join-Path $source 'driver\ev'
    $driverOutput=& (Join-Path $driver 'tapinstall.exe') install (Join-Path $driver 'OemVista.inf') tap0901 2>&1
    $driverExit=$LASTEXITCODE
    $driverOutput | Set-Content -LiteralPath (Join-Path $stateRoot ("tap-{0:D3}.log" -f $info.Number)) -Encoding UTF8
    if($driverExit -notin @(0,1)){throw "TAP installer failed: $driverExit"}
    $deadline=(Get-Date).AddSeconds(30)
    do{
        $added=@(Get-TapAdapters | Where-Object {$_.InterfaceGuid -notin @($before | ForEach-Object {$_.InterfaceGuid})})
        if($added.Count){break}
        Start-Sleep -Milliseconds 500
    }while((Get-Date) -lt $deadline)
    if($added.Count -ne 1){throw 'Could not identify exactly one new TAP adapter. Inspect the log before retrying.'}
    $record.TapGuid=([guid]$added[0].InterfaceGuid).ToString('B').ToUpperInvariant()
    Save-Record $info $record
    $images=@(Get-Images $info $record.TapGuid)
    $null=New-Item -ItemType Directory -Path $info.Directory
    foreach($folder in @('platforms','imageformats','language','image')){
        Copy-Item -LiteralPath (Join-Path $source $folder) -Destination $info.Directory -Recurse
    }
    Get-ChildItem -LiteralPath $source -Filter '*.dll' -File | Copy-Item -Destination $info.Directory
    foreach($folder in @('promote','serviceclient','config','preconfig')){
        $null=New-Item -ItemType Directory -Path (Join-Path $info.Directory $folder)
        if($folder -in @('promote','serviceclient')){
            Get-ChildItem -LiteralPath (Join-Path $source $folder) -Filter '*.dll' -File | Copy-Item -Destination (Join-Path $info.Directory $folder)
        }
    }
    foreach($image in $images){[IO.File]::WriteAllBytes((Join-Path $info.Directory $image.Target),$image.Bytes)}
    $config=(Get-Content -LiteralPath (Join-Path $source 'sysconfig.ini') -Raw).Replace('ClientName = UniVPN',('ClientName = '+$info.Product))
    [IO.File]::WriteAllText((Join-Path $info.Directory 'sysconfig.ini'),$config,[Text.Encoding]::ASCII)
    # PE strings must retain their six-byte product name. A junction supplies
    # that runtime path while the real user-facing directory is UniVPN<number>.
    $null=New-Item -ItemType Junction -Path $info.Alias -Target $info.Directory
    $binary='"'+(Join-Path $info.Alias ('promote\'+$info.Product+'PromoteService.exe'))+'"'
    $null=New-Service -Name $info.Service -BinaryPathName $binary -DisplayName ("UniVPN {0} - native instance" -f $info.Number) -StartupType Manual -Description 'Experimental native UniVPN instance. Launch using its Open-UniVPN command.'
    $record.Status='Ready'
    Save-Record $info $record
    # This launcher reopens the same instance. Running the original script
    # without parameters deliberately creates ANOTHER instance each time.
    $escapedScript=$scriptFile.Replace("'","''")
    $escapedSource=$source.Replace("'","''")
    $command="& '$escapedScript' -SourceDirectory '$escapedSource' -OpenInstance $($info.Number)"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $launcher="@echo off`r`n`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded`r`nif errorlevel 1 pause`r`n"
    [IO.File]::WriteAllText((Join-Path $info.Directory ("Open-UniVPN{0}.cmd" -f $info.Number)),$launcher,[Text.Encoding]::ASCII)
    $record.Files=@($images | Select-Object Target,Hash)
    Save-Record $info $record
    Open-Client $info $record
    Write-Host ("Created. Reopen using: {0}\Open-UniVPN{1}.cmd" -f $info.Directory,$info.Number) -ForegroundColor Green
    Write-Host 'The original client was not modified. Existing clients can now be reopened and connected.'
    Read-Host 'Press Enter to close' | Out-Null
} catch {
    $message=$_.Exception.Message
    if($_.Exception.Data.Contains('VpnRunning') -and -not $SelfTest){
        Add-Type -AssemblyName System.Windows.Forms
        $null=[System.Windows.Forms.MessageBox]::Show($message,'UniVPN：请先退出客户端',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    if($record -and $info -and -not $OpenInstance){
        $record.Status='Failed'
        $record.Error=$message
        try{Save-Record $info $record}catch{}
        # Never uninstall the TAP automatically: it could reload the driver again.
        try{
            $owned=Get-CimInstance Win32_Service -Filter "Name='$($info.Service)'"
            $expected='"'+(Join-Path $info.Alias ('promote\'+$info.Product+'PromoteService.exe'))+'"'
            if($owned -and $owned.PathName -ceq $expected -and $owned.State -ne 'Stopped'){Stop-Service $info.Service}
        }catch{}
    }
    Write-Host ("FAILED: "+$message) -ForegroundColor Red
    if($SelfTest){throw}
    Write-Host 'No original UniVPN files were patched. Partial instances and TAPs are retained for inspection.'
    Read-Host 'Press Enter to close' | Out-Null
    exit 1
} finally {
    if($held -and $mutex){$mutex.ReleaseMutex()}
    if($mutex){$mutex.Dispose()}
}
