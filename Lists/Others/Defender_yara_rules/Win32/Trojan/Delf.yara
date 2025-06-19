rule Trojan_Win32_Delf_DZ_2147553234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.DZ"
        threat_id = "2147553234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.universal101.com/upd" ascii //weight: 1
        $x_1_2 = "x=0/ed=0/ex=1" ascii //weight: 1
        $x_2_3 = "http://aklick.info/d.php?date=" ascii //weight: 2
        $x_10_4 = {52 50 8d 46 48 50 e8 ?? ?? ff ff 83 f8 ff 0f 84 08 01 00 00 89 06 66 81 7e 04 b3 d7 0f 85 c3 00 00 00 66 ff 4e 04 6a 00 ff 36 e8 ?? ?? ff ff 40}  //weight: 10, accuracy: Low
        $x_2_5 = {2a 72 2a 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 75 ?? 72 ?? 6c ?? 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_DA_2147594560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.DA"
        threat_id = "2147594560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Dis iz ToTo V.1 ... Dont worry ! Everything is Okey..." ascii //weight: 100
        $x_50_2 = "C:\\WINDOWS\\SYSTEM32\\autoexec.nt" ascii //weight: 50
        $x_50_3 = "@COPY C:\\WINDOWS\\svhost.bak C:\\WINDOWS\\Adobe.exe" ascii //weight: 50
        $x_10_4 = "MSN_Hacker_v3.exe" ascii //weight: 10
        $x_10_5 = "Windows_Vista_Activation.exe" ascii //weight: 10
        $x_10_6 = "Windows_Vista_Crack.exe" ascii //weight: 10
        $x_10_7 = "Nero_7_Keygen.exe" ascii //weight: 10
        $x_10_8 = "Yahoo_Hacker_V2.exe" ascii //weight: 10
        $x_10_9 = "NAV_2006_Keygen.exe" ascii //weight: 10
        $x_10_10 = "Office_2007_Crack.exe" ascii //weight: 10
        $x_10_11 = "Visual_Studio_2005_Crack.exe" ascii //weight: 10
        $x_10_12 = "Hotmail_Hack_V1.exe" ascii //weight: 10
        $x_10_13 = "C:\\Program Files\\eMule\\Incoming\\" ascii //weight: 10
        $x_10_14 = "C:\\Program Files\\Kazaa\\My Shared\\" ascii //weight: 10
        $x_10_15 = "C:\\Program Files\\StreamCast\\Morpheus\\My Shared\\" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 11 of ($x_10_*))) or
            ((2 of ($x_50_*) and 6 of ($x_10_*))) or
            ((1 of ($x_100_*) and 6 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_BB_2147594842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.BB"
        threat_id = "2147594842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "351"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "ServiceDll.dll" ascii //weight: 100
        $x_100_2 = "ServiceMain" ascii //weight: 100
        $x_100_3 = "WriteProcessMemory" ascii //weight: 100
        $x_20_4 = "DELSer" ascii //weight: 20
        $x_15_5 = "URLDownloadToFileA" ascii //weight: 15
        $x_15_6 = "InternetReadFile" ascii //weight: 15
        $x_10_7 = "SWZ2006" ascii //weight: 10
        $x_10_8 = "WJD2006" ascii //weight: 10
        $x_10_9 = "need dictionary" ascii //weight: 10
        $x_1_10 = "FindExecutableA" ascii //weight: 1
        $x_1_11 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_12 = "FtpGetFileA" ascii //weight: 1
        $x_1_13 = "FtpPutFileA" ascii //weight: 1
        $x_1_14 = "GetProcessMemoryInfo" ascii //weight: 1
        $x_1_15 = "InternetConnectA" ascii //weight: 1
        $x_1_16 = "InternetOpenA" ascii //weight: 1
        $x_1_17 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_18 = "OpenSCManagerA" ascii //weight: 1
        $x_1_19 = "OpenServiceA" ascii //weight: 1
        $x_1_20 = "QueryServiceStatus" ascii //weight: 1
        $x_1_21 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_22 = "RemoveDirectoryA" ascii //weight: 1
        $x_1_23 = "ShellExecuteA" ascii //weight: 1
        $x_1_24 = "ShellExecuteExA" ascii //weight: 1
        $x_1_25 = "socket" ascii //weight: 1
        $x_1_26 = "StartServiceA" ascii //weight: 1
        $x_1_27 = "WinExec" ascii //weight: 1
        $x_1_28 = "TRegistryS" ascii //weight: 1
        $x_5_29 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\" ascii //weight: 5
        $x_5_30 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\" ascii //weight: 5
        $x_1_31 = "%SystemRoot%" ascii //weight: 1
        $x_1_32 = "SeRestorePrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 3 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_5_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 2 of ($x_5_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_100_*) and 2 of ($x_15_*) and 3 of ($x_10_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_5_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 21 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 16 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_15_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_15_*) and 1 of ($x_5_*))) or
            ((3 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_15_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CB_2147598664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CB"
        threat_id = "2147598664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "302"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 200
        $x_30_2 = "Process32Next" ascii //weight: 30
        $x_30_3 = "SeShutdownPrivilege" ascii //weight: 30
        $x_30_4 = "gethostname" ascii //weight: 30
        $x_1_5 = "HTTP/1.1" ascii //weight: 1
        $x_1_6 = "Host:" ascii //weight: 1
        $x_1_7 = "Windows 2000" ascii //weight: 1
        $x_1_8 = "Windows XP" ascii //weight: 1
        $x_1_9 = "Windows 2003" ascii //weight: 1
        $x_1_10 = "{window.location" ascii //weight: 1
        $x_1_11 = "end;name:" ascii //weight: 1
        $x_1_12 = "end;user:" ascii //weight: 1
        $x_1_13 = "portd2:" ascii //weight: 1
        $x_1_14 = "end;kljspass:" ascii //weight: 1
        $x_1_15 = "menameexe:" ascii //weight: 1
        $x_1_16 = "updskljs.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_B_2147598750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.gen!B"
        threat_id = "2147598750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Download_ShowIE_Bykk" ascii //weight: 10
        $x_10_3 = {42 49 54 53 00}  //weight: 10, accuracy: High
        $x_1_4 = "ServiceMain" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_QB_2147599317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.QB"
        threat_id = "2147599317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\windows\\system32\\cmoswar.cad" ascii //weight: 10
        $x_10_2 = "c:\\windows\\system32\\windowsxp.ini" ascii //weight: 10
        $x_5_3 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" ascii //weight: 5
        $x_5_4 = "{ECCBF003-3D4F-49B9-84DD-38234F8D07AB}" ascii //weight: 5
        $x_5_5 = "arun.reg" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_RA_2147601206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.RA"
        threat_id = "2147601206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 53 0c 83 7e 0c 00 75 0b 81 7e 08 c0 5d 02 00 76 48 eb 02 7e 44 8b 46 08 8b 56 0c 2d c0 5d 02 00 83 da 00 83 fa 00 75 09 3d c0 5d 02 00 77 2a eb 02}  //weight: 1, accuracy: High
        $x_1_2 = "Minimize.scf" ascii //weight: 1
        $x_1_3 = "net share" ascii //weight: 1
        $x_1_4 = "shareable wait" ascii //weight: 1
        $x_1_5 = "[InternetShortcut]" ascii //weight: 1
        $x_1_6 = "mciSendStringA" ascii //weight: 1
        $x_1_7 = "FastMM Borland Edition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_AOW_2147601379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AOW"
        threat_id = "2147601379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "Regedit.exe /s" ascii //weight: 5
        $x_5_3 = {77 78 70 53 65 74 75 70 00}  //weight: 5, accuracy: High
        $x_5_4 = "vcshow.dll" ascii //weight: 5
        $x_1_5 = "www1.goads.cn/download/" ascii //weight: 1
        $x_1_6 = "www1.softuu.cn/download/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_AOX_2147601434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AOX"
        threat_id = "2147601434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\MSInfo\\IEFILES.INI" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Micropoint\\Anti-Attack" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "RogueCleaner.exe" ascii //weight: 1
        $x_1_5 = "c:\\Uinstall.bat" ascii //weight: 1
        $x_1_6 = "WoptiClean.exe" ascii //weight: 1
        $x_1_7 = "services.exe" ascii //weight: 1
        $x_1_8 = "MAILMON.EXE" ascii //weight: 1
        $x_1_9 = "Iparmor.exe" ascii //weight: 1
        $x_1_10 = "avpcc.ex" ascii //weight: 1
        $x_1_11 = "avp.exe" ascii //weight: 1
        $x_1_12 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Delf_FC_2147601775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.FC"
        threat_id = "2147601775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "383"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "\\Internet Explorer\\IEXPLORE.EXE" ascii //weight: 100
        $x_50_3 = "AVP.Product_Notification" ascii //weight: 50
        $x_50_4 = "AVP.TrafficMonConnectionTerm" ascii //weight: 50
        $x_10_5 = "sysns.dll" ascii //weight: 10
        $x_10_6 = "ServiceDll" ascii //weight: 10
        $x_10_7 = "userinit.exe" ascii //weight: 10
        $x_10_8 = "cmd /c del " ascii //weight: 10
        $x_10_9 = "svchost.exe -k " ascii //weight: 10
        $x_10_10 = {70 6c 75 67 69 6e 5c [0-8] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_11 = "remote network" ascii //weight: 10
        $x_10_12 = "OpenSCManagerA" ascii //weight: 10
        $x_1_13 = "DisableRegistryTools" ascii //weight: 1
        $x_1_14 = "\\htmlfile\\shell\\open\\command" ascii //weight: 1
        $x_1_15 = "SYSTEM\\CurrentControlSet\\Services\\netns" ascii //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_17 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 8 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CJ_2147602333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CJ"
        threat_id = "2147602333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "107"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_20_2 = "TCustomMemoryStream" ascii //weight: 20
        $x_20_3 = "SetCapture" ascii //weight: 20
        $x_20_4 = "getservbyname" ascii //weight: 20
        $x_20_5 = "ioctlsocket" ascii //weight: 20
        $x_1_6 = "Inverter Bot" ascii //weight: 1
        $x_1_7 = "Fechar Janela do MSN" ascii //weight: 1
        $x_1_8 = "Formata Windows" ascii //weight: 1
        $x_1_9 = "Desabilitar Barra de Tarefas" ascii //weight: 1
        $x_1_10 = "Chama WORM" ascii //weight: 1
        $x_1_11 = "Chama Imagem do FIREHACKER" ascii //weight: 1
        $x_1_12 = "Chama som de ERRO no PC da vitima" ascii //weight: 1
        $x_1_13 = "Open CD/DVD ROM" ascii //weight: 1
        $x_1_14 = "Change Paper of Wall" ascii //weight: 1
        $x_1_15 = "Power OFF Monitor (WIN95)" ascii //weight: 1
        $x_1_16 = "Capturar Imagem da WebCam" ascii //weight: 1
        $x_1_17 = "Enviar MSG." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CJ_2147602333_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CJ"
        threat_id = "2147602333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "224"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_20_2 = "TCustomMemoryStream" ascii //weight: 20
        $x_20_3 = "SetCapture" ascii //weight: 20
        $x_20_4 = "getservbyname" ascii //weight: 20
        $x_20_5 = "ioctlsocket" ascii //weight: 20
        $x_20_6 = "C:\\senhas.txt" ascii //weight: 20
        $x_20_7 = "C:\\tcsystemgeneration.txt" ascii //weight: 20
        $x_20_8 = "ServerSocket1" ascii //weight: 20
        $x_20_9 = "Shell_TrayWnd" ascii //weight: 20
        $x_20_10 = "C:\\webcam.bmp" ascii //weight: 20
        $x_1_11 = "System TC generatio sucefaul" ascii //weight: 1
        $x_1_12 = "GENERATIONES: " ascii //weight: 1
        $x_1_13 = "CODEGENERAD: " ascii //weight: 1
        $x_1_14 = "Set CdAudio Door Open" ascii //weight: 1
        $x_1_15 = "C:\\windows\\Arenito.bmp" ascii //weight: 1
        $x_1_16 = "Windows Live Messenger" ascii //weight: 1
        $x_1_17 = "Command.com /c Del c:\\" ascii //weight: 1
        $x_1_18 = "[Num Lock]" ascii //weight: 1
        $x_1_19 = "keylogger - logs" ascii //weight: 1
        $x_20_20 = "http://orcult.0lx.net/tcgeneration.htm" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_RAT_2147602467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.RAT"
        threat_id = "2147602467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 fc b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 fc 8b c3 e8 ?? ?? ff ff 8b c3 e8 ?? ?? ff ff e8 ?? ?? ff ff ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {75 23 6a 00 8d 45 fc b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ff ff 50 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_3 = "system32\\drivers\\etc\\hosts" ascii //weight: 10
        $x_5_4 = "WinExec" ascii //weight: 5
        $x_1_5 = {31 32 37 2e 30 2e 30 2e 31 20 [0-48] 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {39 2e 39 2e 39 2e 39 20 [0-48] 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_7 = {69 66 20 65 78 69 73 74 [0-32] 67 6f 74 6f [0-32] 74 72 79 [0-32] 64 65 6c 20 25 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CM_2147602813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CM"
        threat_id = "2147602813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00 00 ff ff ff ff 22 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 73 76 63 73 00 ff ff ff ff 34 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 00 ff ff ff ff 09 00 00 00 54 53 45 6e 61 62 6c 65 64}  //weight: 1, accuracy: High
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii //weight: 1
        $x_1_5 = {5c 50 61 72 61 6d 65 74 65 72 73 00 ff ff ff ff 0a 00 00 00 53 65 72 76 69 63 65 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_6 = {43 6f 6d 73 70 65 63 00 ff ff ff ff 09 00 00 00 20 2f 63 20 64 65 6c 20 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_CM_2147603259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CM"
        threat_id = "2147603259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 44 6c 6c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 73 76 63 73 00 ff ff ff ff 34 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74}  //weight: 1, accuracy: High
        $x_1_3 = "htons" ascii //weight: 1
        $x_1_4 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_5 = "CallNextHookEx" ascii //weight: 1
        $x_1_6 = "mouse_event" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_8 = "OpenClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_FL_2147603703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.FL"
        threat_id = "2147603703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SynSend.exe" ascii //weight: 1
        $x_1_2 = "svchost" ascii //weight: 1
        $x_1_3 = {68 74 6f 6e 73 00 00 00 63 6f 6e 6e 65 63 74}  //weight: 1, accuracy: High
        $x_1_4 = {31 39 38 38 2f 31 31 2f 31 31 00 07 73 6f 74 61 69 6b 6b}  //weight: 1, accuracy: High
        $x_1_5 = {e8 f3 95 fe ff 68 0c e5 42 00 8b 03 50 e8 06 96 fe ff 85 c0 74 28 83 3d 10 e5 42 00 01 75 0f 68 00 e5 42 00 6a 00 8b 03 50 e8 0a 96 fe ff}  //weight: 1, accuracy: High
        $x_1_6 = "StartServiceA" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Delf_AR_2147606967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AR"
        threat_id = "2147606967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "http://www.coolmelife.com" ascii //weight: 1
        $x_1_3 = "Microsoft Sectubvy Behave" wide //weight: 1
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 6d 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_CO_2147610993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CO"
        threat_id = "2147610993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 00 [0-3] ff ff ff ff 02 00 00 00 6e 6f 00 00 ff ff ff ff 08 00 00 00 50 6f 70 75 70 4d 67 72 00}  //weight: 5, accuracy: Low
        $x_5_2 = "/cpccpm.php?tmp=" ascii //weight: 5
        $x_4_3 = {2e 65 78 65 00 00 00 00 75 70 64 61 74 65 00}  //weight: 4, accuracy: High
        $x_1_4 = "&ver=" ascii //weight: 1
        $x_1_5 = {55 50 44 41 54 45 00}  //weight: 1, accuracy: High
        $x_1_6 = "SITE IS:" ascii //weight: 1
        $x_1_7 = "VER IS:" ascii //weight: 1
        $x_4_8 = {26 76 3d 31 00 [0-3] ff ff ff ff 05 00 00 00 43 6c 69 63 6b 00 00 00 ff ff ff ff 04 00 00 00 26 63 3d 31 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CR_2147612027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CR"
        threat_id = "2147612027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "wormorkut.php" ascii //weight: 10
        $x_10_3 = "class=useremail" ascii //weight: 10
        $x_10_4 = "del delexec.bat" ascii //weight: 10
        $x_10_5 = "taskkill -f -im ctfmun.exe" ascii //weight: 10
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_CZ_2147612481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.CZ"
        threat_id = "2147612481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_2 = "\\temps\\svchost.exe" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = {68 74 74 70 3a 2f 2f [0-21] 2e 63 6e 2f}  //weight: 10, accuracy: Low
        $x_1_5 = {0a 64 65 6c [0-4] 22 25 73}  //weight: 1, accuracy: Low
        $x_1_6 = {0a 64 65 6c [0-4] 25 30}  //weight: 1, accuracy: Low
        $x_1_7 = {0a 64 65 6c [0-4] 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = "VMProtect" ascii //weight: 1
        $x_1_9 = "TMessager" ascii //weight: 1
        $x_1_10 = "ServiceStop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_FD_2147616460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.FD"
        threat_id = "2147616460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "User-Agent: " ascii //weight: 1
        $x_1_3 = "TaskKill /pid" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\WinNotify" ascii //weight: 1
        $x_1_5 = "TAppInject" ascii //weight: 1
        $x_1_6 = "SetSecurityDescriptorDacl" ascii //weight: 1
        $x_1_7 = {e8 00 00 00 00 5b [0-4] 8d 53 32 [0-4] 8d 43 2a [0-4] 52 ff 10 8b f0 [0-4] 8d 53 72 [0-4] 8d 43 2e [0-4] 52 56 ff 10 83 f8 00 74 02 [0-4] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EG_2147620885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EG"
        threat_id = "2147620885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 2
        $x_2_2 = {75 72 6c 6d 6f 6e 00 00 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_3 = {b8 01 00 00 80 [0-1] e8 ?? fb ff ff 68 ?? ?? ?? 00 ff 15 ?? ?? ?? ?? 8d 4d ?? ba ?? ?? 1b 02 b8 ?? ?? 1b 02 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff 8b d0 8d 45}  //weight: 2, accuracy: Low
        $x_1_4 = {80 3d 10 50 1b 02 01 76 11 6a 00 6a 00 6a 00 68 df fa ed 0e ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {8d 40 00 85 c9 74 19 8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_EI_2147621184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EI"
        threat_id = "2147621184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "151"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "adobe.bat" ascii //weight: 10
        $x_10_3 = "net stop beep" ascii //weight: 10
        $x_10_4 = "&errors[%d]=%d" ascii //weight: 10
        $x_10_5 = "MAIL FROM: <%s>" ascii //weight: 10
        $x_10_6 = "START /WAIT %s /do_work" ascii //weight: 10
        $x_10_7 = "%s?id=%s&tick=%d&ver=%d&smtp=%s" ascii //weight: 10
        $x_1_8 = "/spm/run.exe" ascii //weight: 1
        $x_1_9 = "/spm/update.exe" ascii //weight: 1
        $x_1_10 = "91.207.4.250" ascii //weight: 1
        $x_1_11 = "209.20.130.33" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_EN_2147623507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EN"
        threat_id = "2147623507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sc config dhcp depend= dhcpsrv" ascii //weight: 10
        $x_10_2 = "net start dhcp" ascii //weight: 10
        $x_10_3 = "://suv.ipk8888.cn/count/count.asp?mac=" ascii //weight: 10
        $x_1_4 = "\\dhcp\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_EP_2147623654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EP"
        threat_id = "2147623654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "4324fsdf232" ascii //weight: 2
        $x_2_2 = {70 61 73 73 77 6f 72 64 [0-80] 75 73 65 72 6e 61 6d 65 [0-80] 70 61 73 73 77 6f 72 64 [0-80] 75 73 65 72 6e 61 6d 65}  //weight: 2, accuracy: Low
        $x_2_3 = {44 65 62 69 61 6e 41 63 63 65 73 73 4c 6f 67 69 6e [0-8] 54 52 75 6c 65 73 46 69 72 65 77 61 6c 6c 33}  //weight: 2, accuracy: Low
        $x_5_4 = {51 54 6a 01 6a 00 68 e1 fa ed 0e}  //weight: 5, accuracy: High
        $x_5_5 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 5, accuracy: High
        $x_1_6 = {3d 53 51 4c 4f 4c 45 44 42 2e 31 3b [0-8] 3d 32 32 36 35 31 31 7a}  //weight: 1, accuracy: Low
        $x_1_7 = "zehir2010" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_EQ_2147623733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EQ"
        threat_id = "2147623733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 04 00 00 00 2e 65 78 65 00 00 00 00 ff ff ff ff 40 00 00 00 5c 53 6f 66 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 73 73 6f 63 69 61 74 69 6f 6e 73 5c 00 00 00 00 ff ff ff ff 10 00 00 00 4c 6f 77 52 69 73 6b 46 69 6c 65 54 79 70 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {3b 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 00 ff ff ff ff 0e 00 00 00 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72}  //weight: 1, accuracy: High
        $x_1_3 = {35 00 00 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 00 00 00 ff ff ff ff 0c 00 00 00 4d 73 63 6f 6e 66 69 67 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "OpenSCManagerA" ascii //weight: 1
        $x_1_5 = "ControlService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_ES_2147624028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.ES"
        threat_id = "2147624028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&conteudo=" ascii //weight: 1
        $x_1_2 = {50 4f 53 54 20 2f 65 6d 61 69 6c 2e 70 68 70 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {bf 01 00 00 00 8b 45 fc 8a 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_ET_2147624227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.ET"
        threat_id = "2147624227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 19 00 00 00 e8 ?? ?? ff ff 8b d0 83 c2 61 8d 45 d8 e8 ?? ?? ff ff ff 75 d8 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 07 00 00 00 e8 ?? ?? ff ff 8d 45 d4 e8 ?? ?? ff ff ff 75 d4 b8 19 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 33 c9 ba 44 00 00 00 e8 ?? ?? ff ff c7 46 2c 01 00 00 00 66 c7 46 30 00 00 68 ?? ?? ?? ?? 56 6a 00 6a 00 6a 40 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EZ_2147624987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EZ"
        threat_id = "2147624987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 00 00 57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 f4 01 00 00 e8 ?? ?? fe ff e8 ?? ?? ff ff 83 3b 03 74 05 83 3b 01 75 e7 33 c0 5a 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_GE_2147628299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.GE"
        threat_id = "2147628299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "mfp.bfzz.com/mfp/do.asp" ascii //weight: 1
        $x_1_3 = "?eve=get&username=" ascii //weight: 1
        $x_1_4 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "DEL /a \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_GT_2147631007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.GT"
        threat_id = "2147631007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hacker Society - Trojan Client - by PRChakal" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "System\\CurrentControlSet\\Services\\RemoteAccess" ascii //weight: 1
        $x_1_4 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "TFtpServer" ascii //weight: 1
        $x_1_6 = "ServidorFtp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_HH_2147632688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.HH"
        threat_id = "2147632688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b 45 ec 8b 08 ff 51 38 33 d2 8b 45 ec 8b 08 ff 51 38 ba ?? ?? ?? ?? 8b 45 ec 8b 08 ff 51 38 8d 45 e4 50 8b 45 f8 89 45 d4 c6 45 d8 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List]" ascii //weight: 1
        $x_1_3 = ":*:Enabled:" ascii //weight: 1
        $x_1_4 = "application/vnd.ms-powerpoint, */*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_HY_2147634705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.HY"
        threat_id = "2147634705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[HKEY_CLASSES_ROOT\\CLSID\\{[FolderID]}\\Shell\\Open\\Command]" ascii //weight: 1
        $x_1_2 = "ButtonCreatQuickLaunchClick" ascii //weight: 1
        $x_1_3 = "{1f4de370-d627-11d1-ba4f-00a0c91eedba}" ascii //weight: 1
        $x_1_4 = "\\Internet Explorer.lnk" ascii //weight: 1
        $x_1_5 = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_NC_2147635925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.NC"
        threat_id = "2147635925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 5b f7 fb 85 d2 75 0f}  //weight: 2, accuracy: High
        $x_1_2 = "mac=%s&PcType=%s&AvName=" ascii //weight: 1
        $x_1_3 = "vip.eloaz.com/admin" ascii //weight: 1
        $x_2_4 = "mutex_senddata_.la" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_HZ_2147636470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.HZ"
        threat_id = "2147636470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vmware.exe|" ascii //weight: 1
        $x_1_2 = "*google*.txt" ascii //weight: 1
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 ff ff ff ff 17 00 00 00 44 69 73 61 62 6c 65 53 63 72 69 70 74 44 65 62 75 67 67 65 72 49 45}  //weight: 1, accuracy: High
        $x_1_4 = "groups.google.com/grphp?hl=zh-CN&ned=cn&tab=ng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_ND_2147637020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.ND"
        threat_id = "2147637020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dnf360.com" ascii //weight: 1
        $x_1_2 = "dnfwg.com" ascii //weight: 1
        $x_1_3 = "wgxz.net" ascii //weight: 1
        $x_1_4 = "Thunder.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_NE_2147637021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.NE"
        threat_id = "2147637021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 07 68 84 00 00 00 eb 05 68 85 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e0 10 2b c3 99 f7 ff}  //weight: 1, accuracy: High
        $x_1_3 = {25 01 00 00 80 79 05 48 83 c8 fe 40}  //weight: 1, accuracy: High
        $x_1_4 = "\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_5 = "%s/UpdateFiles/update%d.exe" ascii //weight: 1
        $x_1_6 = "/update.aspx?feedback=success&ver=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Delf_II_2147637028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.II"
        threat_id = "2147637028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7322.com" ascii //weight: 1
        $x_1_2 = "my115.net" ascii //weight: 1
        $x_2_3 = {44 65 6c 54 65 6d 70 2e 62 61 74 00 ff ff ff ff 05 00 00 00 3a 52 64 65 6c 00 00 00 ff ff ff ff 04 00 00 00 64 65 6c 20 00 00 00 00 ff ff ff ff 09 00 00 00 69 66 20 65 78 69 73 74 20}  //weight: 2, accuracy: High
        $x_2_4 = {20 67 6f 74 6f 20 52 64 65 6c 00 00 ff ff ff ff 0f 00 00 00 64 65 6c 20 44 65 6c 54 65 6d 70 2e 62 61 74}  //weight: 2, accuracy: High
        $x_2_5 = {e5 db d3 ce e4 af c0 c0 c6 f7 2e 6c 6e 6b 00 00 ff ff ff ff 09 00 00 00 33 36 30 73 65 2e 65 78 65 00 00 00 ff ff ff ff 07 00 00 00 61 62 63 2e 65 78 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_IJ_2147637522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IJ"
        threat_id = "2147637522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 2e 31 04 00 00 00 00 10 40 00 48 00 00 00 00 10 40 00 0a 6d 69 6e 69 38 55 6e 69 74 31 90}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 20 25 30 00 ff ff ff ff 0e 00 00 00 7b 77 69 6e 7d 5c 72 61 63 63 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 00 00 00 7b 65 31 37 64 34 66 63 30 2d 35 35 36 34 2d 31 31 64 31 2d 38 33 66 32 2d 30 30 61 30 63 39 30 64 63 38 34 39 7d 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 0d 0a 00 00 00 00 ff ff ff ff 1a 00 00 00 7b 70 66 7d 5c 52 69 73 69 6e 67 5c 52 61 76 5c 52 73 4d 61 69 6e 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_IM_2147637677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IM"
        threat_id = "2147637677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zmp.txt" ascii //weight: 1
        $x_1_2 = "tiwlbnapgjsp4qyzsylldu3ylv4rnvcr2wejder4py9rvmdc" ascii //weight: 1
        $x_1_3 = "d9adyz93472kb63z521t6e80wqpi56znb16fya6im3dr3xwe" ascii //weight: 1
        $x_1_4 = "GET /data/{aid}?cli=10&" ascii //weight: 1
        $x_1_5 = {44 32 30 30 39 30 37 30 36 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 32 32 2e 37 33 2e 32 31 38 2e 32 30}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 6f 6e 6c 69 6e 65 32 2f 3f 73 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 76 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 6e 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 72 6e 64 3d}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 6c 69 73 74 32 2f 3f 73 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 61 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 72 6e 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Delf_IN_2147637750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IN"
        threat_id = "2147637750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6e 4e 75 6f 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 79 69 65 ?? ?? ?? ?? ?? ?? 73 65 74 75 70 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 78 7a 31 39 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {71 72 6e 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {78 7a 7a 2f 10 00 25 64 ?? ?? 64 6b 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_IO_2147637796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IO"
        threat_id = "2147637796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".gtb\\PersistentHandler" ascii //weight: 1
        $x_1_2 = {6f 76 2e 6f 76 65 72 74 6e 2e 63 6f 6d 2f [0-32] 2f 65 78 65 2f 75 70 5f 74 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {64 6f 77 6e 2e 6f 76 65 72 74 6e 2e 63 6f 6d 2f [0-32] 2f 62 68 6f 6e 2f}  //weight: 1, accuracy: Low
        $x_1_4 = "IPerPropertyBrowsingD" ascii //weight: 1
        $x_1_5 = "software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_IT_2147639087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IT!dll"
        threat_id = "2147639087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">Hbho~vItto>GHbho~v()Ghx5~c~" ascii //weight: 1
        $x_1_2 = ";xtu}r|;KtwrxbZ|~uo;hozio&znot" ascii //weight: 1
        $x_1_3 = ";hozio;KtwrxbZ|~uo" ascii //weight: 1
        $x_1_4 = ";360deepscan;DSMain;krnl360svc;egui;ekrn;kissvc;kswebshield;ZhuDongFangYu;SuperKiller;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_IU_2147639088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IU!dll"
        threat_id = "2147639088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "!@#wangji&hyz**" ascii //weight: 1
        $x_1_2 = "ydgidcnafg.dat" ascii //weight: 1
        $x_1_3 = "udp\\hjob123\\com" ascii //weight: 1
        $x_1_4 = {2e 6c 6c 61 64 73 2e 63 6e [0-5] 2f 69 65 62 61 72 2f 74 74 65 73 74 2e 61 73 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_IV_2147639611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IV"
        threat_id = "2147639611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "S!o@u#g$o%u^C!l@i#c%k" ascii //weight: 1
        $x_1_2 = "aaa.82245.com:8080/sogou/sogou_click_jsxs.php" ascii //weight: 1
        $x_1_3 = {74 6a 2e 38 32 32 34 35 2e 63 6f 6d 3a [0-4] 2f 74 6a [0-1] 2f 43 6f 75 6e 74 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_4 = {53 61 66 65 74 72 61 79 5c 20 2f 64 20 32 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Delf_IX_2147641110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.IX!dll"
        threat_id = "2147641110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\srvsys\\" ascii //weight: 1
        $x_1_2 = "\\wintemp_64\\" ascii //weight: 1
        $x_2_3 = ".6dudu.com" ascii //weight: 2
        $x_2_4 = "bibibei.exe" ascii //weight: 2
        $x_2_5 = "122.224.9.113:8022/Insertbz.aspx?mci=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_JE_2147641124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.JE"
        threat_id = "2147641124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 33 c9 8a 50 02 33 db 8a 48 01 8a 18 89 5d f4 83 c0 03 8b 1c 96 8b 7d f4 03 9c 8e 00 04 00 00 03 9c be 00 08 00 00 8b 7d e8 c1 fb 10}  //weight: 1, accuracy: High
        $x_1_2 = {66 69 6c 65 63 6f 75 6e 74 00 00 00 ff ff ff ff 0c 00 00 00 64 6f 77 6e 6c 6f 61 64 66 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = "Directory\\shell\\find\\ddeexec" ascii //weight: 1
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 64 65 6c 6c 69 73 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_JG_2147642015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.JG"
        threat_id = "2147642015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 05 bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e0 3b 5d e4 7f ?? 81 c3 ff 00 00 00 2b 5d e4 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 e7 61 6e 64 6f 20 55 50 44 41 54 45}  //weight: 1, accuracy: High
        $x_1_3 = "?a=c&s=%s&p=%d&id=%s" ascii //weight: 1
        $x_1_4 = "Projetos\\javan\\bho_atual\\untFuncoes.pas" ascii //weight: 1
        $x_1_5 = "Carregando do conte" ascii //weight: 1
        $x_1_6 = "uma cpl : WshShell.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Delf_MW_2147642090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.MW!dll"
        threat_id = "2147642090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 00 00 2e 6c 69 6e 6b}  //weight: 1, accuracy: High
        $x_1_2 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 54 50 6c 61 79 65 72 00 00 00 [0-16] 54 50 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateFactorys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_RRB_2147642620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.RRB"
        threat_id = "2147642620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xx-!@#$xx" ascii //weight: 1
        $x_1_2 = "<iframe src=\"http://localhost:97/a.htm\" />" ascii //weight: 1
        $x_1_3 = "_jdfwkey=cw%d|http://www.gk66.cn/" ascii //weight: 1
        $x_1_4 = {24 24 61 2e 62 61 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 74 72 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_JN_2147643308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.JN"
        threat_id = "2147643308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "\\SYSTEM\\CurrentControlSet\\Services\\sysafety" ascii //weight: 1
        $x_1_3 = "\\System32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "178.63.203.133" ascii //weight: 1
        $x_1_5 = {77 77 77 2e 76 6b [0-8] 2e 72 75}  //weight: 1, accuracy: Low
        $x_1_6 = "Controller of computer safety" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Delf_KB_2147645925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KB"
        threat_id = "2147645925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 f4 8b 07 8a 44 18 ff 8b d0 8b 4d f8 8a 4c 31 ff 32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 ?? 8b f0 81 e6 ff 00 00 00 8b c7 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "winnewdll.dll" ascii //weight: 1
        $x_1_3 = "windowsproxy.org/win.lac" ascii //weight: 1
        $x_1_4 = "css/logs/add.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KK_2147647533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KK"
        threat_id = "2147647533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 1, accuracy: Low
        $x_1_2 = "[craziii" ascii //weight: 1
        $x_1_3 = ":\\Arquivos de programas\\Scpad" ascii //weight: 1
        $x_1_4 = "\\windows\\kilinh.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KO_2147648229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KO"
        threat_id = "2147648229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.soso.com/q?w=%s&lr=&sc=web&ch=w.p&filter=1&num=10&pg=%d" ascii //weight: 2
        $x_2_2 = "http://www.google.com/search?complete=1&q=%s" ascii //weight: 2
        $x_2_3 = "TAdsInfo4" ascii //weight: 2
        $x_3_4 = "z_hstemp%.3d.html" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KP_2147648255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KP"
        threat_id = "2147648255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "{8FC5F779-A5B3-21759-9C81-9FB010E01CBC}" ascii //weight: 3
        $x_4_2 = "fi%s\\%scdu.dll" ascii //weight: 4
        $x_1_3 = "TStartThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KQ_2147648340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KQ"
        threat_id = "2147648340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Microsoft\\ntldr.dll" ascii //weight: 3
        $x_4_2 = {ff ff ff ff 05 00 00 00 53 54 20 2f 31 00 00 00 ff ff ff ff 03 00 00 00 73 74 65 00 ff ff ff ff 03 00 00 00 6d 61 69 00 ff ff ff ff 03 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KU_2147649062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KU"
        threat_id = "2147649062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 5c 68 6f 73 74 73 1e 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 00 2f 00 3f 00 69 00 73 00 6c 00 65 00 6d 00 3d 00 68 00 6f 00 73 00 74 00 73 00 26 00 67 00 75 00 76 00 65 00 6e 00 6c 00 69 00 6b 00 3d 00 64 00 77 00 6d 00 08 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_LI_2147652320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.LI"
        threat_id = "2147652320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 1
        $x_1_2 = "\\Micro softHelp\\" wide //weight: 1
        $x_1_3 = "$$WindowsXp.bat" wide //weight: 1
        $x_1_4 = "UCC2011.COM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_LK_2147653710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.LK"
        threat_id = "2147653710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\JetSwap" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\safesurf.exe" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\videos2" ascii //weight: 1
        $x_1_4 = {2e 31 67 62 2e 72 75 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_LL_2147653928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.LL"
        threat_id = "2147653928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 1f 00 0f 00 e8 ?? ?? ff ff a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75 ?? 68 ?? ?? 41 00 6a 04 6a 00 6a 04 6a 00 6a ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 10 33 c9 89 08 8b c2 e8 ?? ?? ff ff c3 8b c0 1d 00 00 00 08 33 41 00 d8 34 41 00 00 33 41 00}  //weight: 1, accuracy: Low
        $x_1_3 = {54 4e 74 48 6f 6f 6b [0-1] 43 6c 61 73 73}  //weight: 1, accuracy: Low
        $x_1_4 = {68 6f 6f 6b [0-1] 44 6c 6c 2e 64 6c 6c [0-4] 45 6e 64 48 6f 6f 6b [0-4] 53 74 61 72 74 48 6f 6f 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_KX_2147656319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.KX"
        threat_id = "2147656319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d:\\360\\360Safe.reg" ascii //weight: 1
        $x_1_2 = "d:\\360Safe.reg" ascii //weight: 1
        $x_1_3 = "d:\\360.reg" ascii //weight: 1
        $x_5_4 = {68 c8 00 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 c8 00 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 6a 64 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_LX_2147657688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.LX"
        threat_id = "2147657688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "netsh firewall set opmode disable" ascii //weight: 1
        $x_1_2 = "\\start menu\\programs\\startup" ascii //weight: 1
        $x_1_3 = "regsvr32 /s " ascii //weight: 1
        $x_1_4 = "software\\borland\\delphi\\locales" ascii //weight: 1
        $x_1_5 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_6 = {5a 58 85 ff 75 0c 85 d2 74 03 ff 4a f8 e8 ?? ?? ff ff 5a 5f 5e 5b 58 8d 24 94 ff e0}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_LZ_2147658021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.LZ"
        threat_id = "2147658021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 00 10 40 00 b9 44 90 00 00 49 80 34 0f ?? 85 c9 75 f7 5f 59 c9 e9 ab ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_MF_2147659624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.MF"
        threat_id = "2147659624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Windows\\CurrentVersion" wide //weight: 1
        $x_1_2 = {bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ?? 80 f3 01 47 4e 75 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_MK_2147693611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.MK"
        threat_id = "2147693611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6d 67 72 73 [0-8] 53 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_2 = ":adel" ascii //weight: 1
        $x_1_3 = "choice /t 5 /d y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_GL_2147720091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.GL!bit"
        threat_id = "2147720091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 00 00 00 ff ff ff ff 07 00 00 00 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 65 67 61 70 65 73 74 72 00 00 00 ff ff ff ff 09 00 00 00 6d 65 67 61 70 65 65 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_J_2147743803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.J!ibt"
        threat_id = "2147743803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1a 32 1e 88 19 41 46 42 48 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0a 32 0e 8b 7d e8 88 0f ff 45 e8 46 42 48 75 ef}  //weight: 1, accuracy: High
        $x_1_3 = "8303027835B6869586F743721D4F1AB42112215D8E1C80E33" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_SA_2147779445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.SA!MTB"
        threat_id = "2147779445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32 advpack.dll,DelNodeRunDLL32 %s" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\920" ascii //weight: 1
        $x_1_3 = "\\dxminiax.cab" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\cacls.exe" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\system32\\asr_pfu.exe" ascii //weight: 1
        $x_5_6 = "F:\\Office\\Target\\x86\\ship\\postc2r\\x-none\\wordconv" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delf_MBK_2147781409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.MBK!MTB"
        threat_id = "2147781409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System\\CurrentControlSet\\Control\\Keyboard Layouts" wide //weight: 1
        $x_1_2 = "PATCH" wide //weight: 1
        $x_1_3 = "FCorpLAB2019" wide //weight: 1
        $x_1_4 = "avgggggg.exe" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_7 = "inf.txt" wide //weight: 1
        $x_1_8 = "http://controle.supermercadoimperial.com.br/modulos/contador/fatal/bit/go.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_UNK_2147786568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.UNK!MTB"
        threat_id = "2147786568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://zb.66wangba.com/zhuobiao" wide //weight: 1
        $x_1_2 = "Applications\\360chrome.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = {bf 19 00 02 00 81 cf 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 10 85 d2 74 1c c7 00 00 00 00 00 8b 4a f8 49 7c 10 f0 ff 4a f8 75 0a 50 8d 42 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_AF_2147787514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AF!MTB"
        threat_id = "2147787514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Glyph.Data" ascii //weight: 3
        $x_3_2 = "laWebSiteAddressClick" ascii //weight: 3
        $x_3_3 = "laWebSiteAddressMouseEnter" ascii //weight: 3
        $x_3_4 = "laWebSiteAddressMouseLeave" ascii //weight: 3
        $x_3_5 = "StudMailer" ascii //weight: 3
        $x_3_6 = "AdjustWindowRectEx" ascii //weight: 3
        $x_3_7 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_8 = "GetKeyboardState" ascii //weight: 3
        $x_3_9 = "GetKeyboardLayout" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKR_2147789168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKR!MTB"
        threat_id = "2147789168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vdd.dat" ascii //weight: 1
        $x_1_2 = "!!c!!o!!n!!i!!m!!e!!!.!!e!!x!!e" ascii //weight: 1
        $x_1_3 = "y  c .  b  a  t" ascii //weight: 1
        $x_1_4 = "3.vbs" ascii //weight: 1
        $x_1_5 = "q.rar" ascii //weight: 1
        $x_1_6 = "C  A  P  T  U  R  A  W  E  B  C  A  M" ascii //weight: 1
        $x_1_7 = "BarClientView.exe" wide //weight: 1
        $x_1_8 = "sc config kxescore start= disabled" ascii //weight: 1
        $x_1_9 = "!!!!S!!n!!i!!p!!e!!S!!!w!!o!!r!!!d!!!.!!e!!x!!!e!!" ascii //weight: 1
        $x_1_10 = "Sunward Information Technology Co.Ltd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EM_2147813939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EM!MTB"
        threat_id = "2147813939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Viable Solution.pcr" ascii //weight: 3
        $x_3_2 = "LoadKeyboardLayoutA" ascii //weight: 3
        $x_3_3 = "Access violation at address" ascii //weight: 3
        $x_3_4 = "KeyDesc8eA" ascii //weight: 3
        $x_3_5 = "Glyph.Data" ascii //weight: 3
        $x_3_6 = "AutoHotkeys" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EM_2147813939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EM!MTB"
        threat_id = "2147813939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "antidebuggers" ascii //weight: 1
        $x_1_2 = "antivirtuals" ascii //weight: 1
        $x_1_3 = "NyOWB0b35xXWVtZ2k" ascii //weight: 1
        $x_1_4 = "DCPbase64" ascii //weight: 1
        $x_1_5 = "BAntiReversMod" ascii //weight: 1
        $x_1_6 = "JXIzRSaFVcOiQiI1E6JFVDSk4yT3t0VDFwTHVmSn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EN_2147813940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EN!MTB"
        threat_id = "2147813940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DONGA" ascii //weight: 3
        $x_3_2 = "ICEXP" ascii //weight: 3
        $x_3_3 = {42 4d 36 63 00 00 00 00 00 00 76 00 00 00 28 00 00 00 3f 01 00 00 9e 00 00 00 01}  //weight: 3, accuracy: High
        $x_3_4 = "OnKeyPress" ascii //weight: 3
        $x_3_5 = "GetMonitorInfoW" ascii //weight: 3
        $x_3_6 = "ShellFolder" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EN_2147813940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EN!MTB"
        threat_id = "2147813940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "P.Stone" ascii //weight: 1
        $x_1_2 = "StikyNot.exe" ascii //weight: 1
        $x_1_3 = "SyncHost.exe" ascii //weight: 1
        $x_1_4 = "StikyNot_yakuza" ascii //weight: 1
        $x_1_5 = "Encrypted by Stone/UCF" ascii //weight: 1
        $x_1_6 = "PowerLame PE-ExeEnCrypter!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_NB_2147814558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.NB!MTB"
        threat_id = "2147814558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BitBlt" ascii //weight: 3
        $x_3_2 = "DragKind" ascii //weight: 3
        $x_3_3 = "Dock zone has no control" ascii //weight: 3
        $x_3_4 = "Don HO don.h@free.fr" ascii //weight: 3
        $x_3_5 = "Notepad++.exe" ascii //weight: 3
        $x_3_6 = "CopyEnhMetaFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_AG_2147819837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AG!MTB"
        threat_id = "2147819837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinSock 2.0" ascii //weight: 1
        $x_1_2 = "MPGoodStatus" ascii //weight: 1
        $x_1_3 = "slash\\User" ascii //weight: 1
        $x_1_4 = "New Userownloads\\The" ascii //weight: 1
        $x_1_5 = "slash.exemaster\\" ascii //weight: 1
        $x_1_6 = "slashttings.ini" ascii //weight: 1
        $x_1_7 = "46.246.122.188#PAD" ascii //weight: 1
        $x_1_8 = "GetACP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EC_2147841685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EC!MTB"
        threat_id = "2147841685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b d6 b1 19 8b c7 48 85 c0 7c 07 40 30 0a 42 48 75 fa 5f 5e 5b c3}  //weight: 6, accuracy: High
        $x_1_2 = "FADGRQSPCUTWVihj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EC_2147841685_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EC!MTB"
        threat_id = "2147841685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "120.55.196.60" ascii //weight: 1
        $x_1_2 = "QFNTU1NTU1NTU1NTU1NTU1NTU1NTQA==" ascii //weight: 1
        $x_1_3 = "RunUrlKew" ascii //weight: 1
        $x_1_4 = "QFdXV1dXV1dXQA==" ascii //weight: 1
        $x_1_5 = "QDExMTExMTExQA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_EC_2147841685_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.EC!MTB"
        threat_id = "2147841685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-MpPreference -ExclusionPath C:" ascii //weight: 1
        $x_1_2 = "SU1ZWVVk" ascii //weight: 1
        $x_1_3 = "V3hleHl3JGl2dnN2Pg==" ascii //weight: 1
        $x_1_4 = "YE1JVVVRYA==" ascii //weight: 1
        $x_1_5 = "RDtdSk9UVUJNTUZTXQ==" ascii //weight: 1
        $x_1_6 = "MGd6Zw==" ascii //weight: 1
        $x_1_7 = "eHZ5aQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_AT_2147896079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.AT!MTB"
        threat_id = "2147896079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "del \"C:\\myapp.exe\" /q" ascii //weight: 3
        $x_3_2 = "if exist \"C:\\myapp.exe\" goto try" ascii //weight: 3
        $x_3_3 = "WinExec" ascii //weight: 3
        $x_3_4 = "GetVolumeInformationA" ascii //weight: 3
        $x_3_5 = "GetStartupInfoA" ascii //weight: 3
        $x_3_6 = "GetKeyboardType" ascii //weight: 3
        $x_3_7 = "GetCommandLineA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_NS_2147926475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.NS!MTB"
        threat_id = "2147926475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "222.73.85.117" ascii //weight: 2
        $x_2_2 = "116.9.143.112" ascii //weight: 2
        $x_1_3 = "blcgzwl.rar" ascii //weight: 1
        $x_1_4 = "wenyong006" ascii //weight: 1
        $x_1_5 = "fzckcksj" ascii //weight: 1
        $x_1_6 = "Privileged instruction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKN_2147935404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKN!MTB"
        threat_id = "2147935404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {23 c2 c1 e0 03 01 45 f4 8b 4d f4 33 c0 8a 01 89 45 f0 85 c0}  //weight: 4, accuracy: High
        $x_1_2 = "%TEMP%\\SyncClipRoot\\" ascii //weight: 1
        $x_1_3 = "%TEMP%\\vmware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKL_2147935611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKL!MTB"
        threat_id = "2147935611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.bat" ascii //weight: 1
        $x_1_2 = "@Echo OFF" ascii //weight: 1
        $x_1_3 = "!!!!I!!c!!e!!S!!w!!o!!r!!d!!.!!e!!x!!!e!!" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup" ascii //weight: 1
        $x_1_5 = "C  A  P  T  U  R  A  W  E  B  C  A  M  " ascii //weight: 1
        $x_1_6 = "y  c .  b  a  t" ascii //weight: 1
        $x_1_7 = "1.vbs" ascii //weight: 1
        $x_1_8 = "del.bat" ascii //weight: 1
        $x_1_9 = "q.rar" ascii //weight: 1
        $x_1_10 = "r  u  n      u  r  l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKM_2147936283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKM!MTB"
        threat_id = "2147936283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 f8 03 c6 40 99 89 45 f0 89 55 f4 eb ?? 46 4f 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKP_2147937533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKP!MTB"
        threat_id = "2147937533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 77 14 89 7e 0c c7 46 ?? ?? ?? ?? ?? 8d 47 38 89 46 14 c7 47 ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 88 47 08 8b d7 a1}  //weight: 1, accuracy: Low
        $x_1_2 = "dRANGERO" ascii //weight: 1
        $x_1_3 = "OMNTAAAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delf_OKO_2147944118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delf.OKO!MTB"
        threat_id = "2147944118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute" ascii //weight: 1
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "Synaptics.exe" ascii //weight: 1
        $x_2_4 = "Injecting" ascii //weight: 2
        $x_2_5 = ".xlsx" ascii //weight: 2
        $x_1_6 = "Auto Update -> Active" ascii //weight: 1
        $x_1_7 = "Auto Update -> Deactive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

