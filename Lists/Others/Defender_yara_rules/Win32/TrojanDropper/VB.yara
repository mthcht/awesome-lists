rule TrojanDropper_Win32_VB_A_2147497059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.A"
        threat_id = "2147497059"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del /f del.bat" wide //weight: 1
        $x_1_2 = "t58chat_398085.exe" wide //weight: 1
        $x_1_3 = "115br.exe" ascii //weight: 1
        $x_1_4 = "tao.ico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_2147506709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB"
        threat_id = "2147506709"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "222"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Generic Host Process for Win32 Services" ascii //weight: 10
        $x_1_2 = "csrss.exe" ascii //weight: 1
        $x_1_3 = ":\\WINDOWS\\Help\\.HLP" ascii //weight: 1
        $x_100_4 = "www.baidu.com|www.qq.com|www.sina.com.cn|www.sohu.com" wide //weight: 100
        $x_10_5 = {53 00 2d 00 31 00 2d 00 35 00 2d 00 32 00 31 00 [0-32] 43 00 6c 00 61 00 73 00 73 00 [0-32] 5c 00 74 00 6d 00 70 00 2e 00 72 00 65 00 67 00 [0-32] 52 00 65 00 67 00 65 00 64 00 69 00 74 00 20 00 2f 00 73 00 20 00}  //weight: 10, accuracy: Low
        $x_1_6 = "\\mmtmp.bat" wide //weight: 1
        $x_1_7 = "\\temp.reg" wide //weight: 1
        $x_100_8 = "tiwlbnapgjsp4qyzsylldu3ylv4rnvcr2wejder4py9rvmdc" wide //weight: 100
        $x_10_9 = "http://www.baidu.com/$$http://www.baidu.com/s?wd=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_GM_2147593200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.GM"
        threat_id = "2147593200"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 [0-22] 2e 00 65 00 78 00 65 00}  //weight: 30, accuracy: Low
        $x_10_2 = "\\captura\\joinner\\Project1.vbp" wide //weight: 10
        $x_10_3 = "\\system32\\OSSMTP.dll" wide //weight: 10
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 2
        $x_2_5 = "wscript.shell" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_BC_2147597734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.BC"
        threat_id = "2147597734"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AJ:\\MASTER\\ad_compiler\\moy.exe\\balvanka\\ZAG.vbp" wide //weight: 1
        $x_1_2 = "vvgeowbv.exe" wide //weight: 1
        $x_1_3 = "loader.bin" wide //weight: 1
        $x_1_4 = "GetSystemDirectory" ascii //weight: 1
        $x_10_5 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_AZ_2147598039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.AZ"
        threat_id = "2147598039"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 55 00 73 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 20 00 4e 00 6f 00 72 00 6b 00 5c 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 75 62 62 00 53 74 75 62 00 00 50 72 6f 6a 65 63 74 31}  //weight: 1, accuracy: High
        $x_1_3 = "DllFunctionCall" ascii //weight: 1
        $x_1_4 = "ProcCallEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_DH_2147599332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DH"
        threat_id = "2147599332"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MSVBVM60.DLL" ascii //weight: 100
        $x_1_2 = "getwinpath" ascii //weight: 1
        $x_1_3 = "WithRVStub" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_6 = "RegSetValueExA" ascii //weight: 1
        $x_1_7 = "\\ZiG\\Desktop\\projects\\Art Of Deception\\stub\\RVStub.vbp" wide //weight: 1
        $x_1_8 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_9 = "\\ms.exe" wide //weight: 1
        $x_1_10 = "\\win.bat" wide //weight: 1
        $x_1_11 = "13.09.2006 12:35:41" wide //weight: 1
        $x_1_12 = "Windows Dir" wide //weight: 1
        $x_1_13 = "System32 Dir" wide //weight: 1
        $x_1_14 = "Programs Dir" wide //weight: 1
        $x_1_15 = "All Users Startup" wide //weight: 1
        $x_1_16 = "MyPictures Dir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_DK_2147599601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DK"
        threat_id = "2147599601"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "181"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "DeCrSvr" ascii //weight: 10
        $x_10_2 = "FalseSocket" ascii //weight: 10
        $x_10_3 = "VB6DE.DLL" ascii //weight: 10
        $x_10_4 = "stub.shark" ascii //weight: 10
        $x_10_5 = "Projekt1" ascii //weight: 10
        $x_10_6 = "Svr.Socket" ascii //weight: 10
        $x_10_7 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_8 = "Zombie_GetTypeInfo" ascii //weight: 10
        $x_1_9 = "@-70BF-4C72-94F3-BE5C" wide //weight: 1
        $x_1_10 = "*\\AE:\\sharK\\2.2\\Server\\Projekt1.vbp" wide //weight: 1
        $x_100_11 = {20 44 65 43 72 53 76 72 00 69 6c 65 20 00 61 72 44 69 72 20 26 00 00 00 00 88 00 00 00 00 00 00 00 02 00 00 00 0b 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 00 00 90 00 00 00 a0 00 00 00 01 00 00 00 52 75 6e 41 01 20 28 50 72 6f 00 00 20 3d 20 46 61 6c 73 65 53 6f 63 6b 65 74 00 20}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 8 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_DP_2147600382_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DP"
        threat_id = "2147600382"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\exe crypter\\server\\" wide //weight: 1
        $x_1_2 = "tmp.tmp.tmp1" wide //weight: 1
        $x_1_3 = "`*[S-P-L-I-T]*`!" wide //weight: 1
        $x_1_4 = {57 72 69 74 65 44 61 74 61 00 00 00 53 6f 75 72 63 65 00 00 44 65 73 74 69 6e 61 74 69 6f 6e 00 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_BB_2147600919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.BB"
        threat_id = "2147600919"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BstKLOG_Maileer" ascii //weight: 1
        $x_1_2 = "tmrFTPYOLLAMASURESI" ascii //weight: 1
        $x_1_3 = "tmrFORMAIL" ascii //weight: 1
        $x_1_4 = "ActiveX Debugger.exe" ascii //weight: 1
        $x_1_5 = "Windows XP Profesionnel" wide //weight: 1
        $x_10_6 = "activexdebugger32" ascii //weight: 10
        $x_10_7 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_8 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 10
        $x_10_9 = "D:\\@liihsan2397\\Belgelerim\\VB_Projelerim\\hAckEr\\KeyLOGERs\\For BstKLOG Send Mailleer NOCX\\BstKLOG_Maileer.vbp" wide //weight: 10
        $x_10_10 = {c7 45 fc 0f 00 00 00 c7 85 0c ff ff ff ?? ?? 40 00 c7 85 04 ff ff ff 08 00 00 00 8d 95 04 ff ff ff 8d 4d 98 ff 15 ?? ?? ?? ?? 8d 45 98 50 8d 4d 88 51 ff 15 ?? ?? ?? ?? c7 85 fc fe ff ff ?? ?? 40 00 c7 85 f4 fe ff ff 08 00 00 00 6a 00 8d 55 88 52 8d 85 f4 fe ff ff 50 8d 8d 78 ff ff ff 51 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 dc 8d 95 78 ff ff ff 52 8d 45 88 50 8d 4d 98 51 6a 03}  //weight: 10, accuracy: Low
        $x_10_11 = {c7 85 58 ff ff ff ?? ?? 40 00 c7 85 50 ff ff ff 08 00 00 00 c7 85 48 ff ff ff ?? ?? 40 00 c7 85 40 ff ff ff 08 00 00 00 8d 45 94 50 8d 8d 50 ff ff ff 51 8d 55 84 52 ff 15 ?? ?? 40 00 50 8d 85 40 ff ff ff 50 8d 8d 74 ff ff ff 51 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 8d 95 74 ff ff ff 52 8d 45 84 50 8d 4d 94 51 6a 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_GS_2147602150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.GS"
        threat_id = "2147602150"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\COM\\csrss.exe" wide //weight: 1
        $x_1_2 = "System\\CurrentControlSet\\Services\\EventLog\\" wide //weight: 1
        $x_1_3 = "SampleVB6Service" wide //weight: 1
        $x_1_4 = "WriteEvents.WriteEventsLog" wide //weight: 1
        $x_1_5 = "QoS Manager" wide //weight: 1
        $x_1_6 = {53 61 6d 70 6c 65 00 00 4e 54 53 65 72 76 69 63 65 00 00 00 6d 6f 64 43 6f 6d 6d 6f 6e}  //weight: 1, accuracy: High
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_GR_2147602151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.GR"
        threat_id = "2147602151"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\mmtmp.bat" wide //weight: 1
        $x_1_2 = "net start QoSvc" wide //weight: 1
        $x_1_3 = {43 00 55 00 53 00 54 00 4f 00 4d 00 00 00 00 00 18 00 00 00 5c 00 43 00 6f 00 6d 00 5c 00 51 00 6f 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 6e 73 74 61 6c 6c 00 61 70 70 00 00 61 70 70}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_GT_2147602469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.GT"
        threat_id = "2147602469"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nhaalclkiemr" ascii //weight: 10
        $x_10_2 = "IAlgorithm_DecryptString" ascii //weight: 10
        $x_1_3 = "taskkill /F /IM" wide //weight: 1
        $x_1_4 = {63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 00 00 08 00 00 00 74 00 65 00 6d 00 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "/v DoNotAllowExceptions /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_10_6 = "MSVBVM60.DLL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_BG_2147603303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.BG"
        threat_id = "2147603303"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB5!6&vb6chs.dll" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\vb6mini\\VB6.OLB" ascii //weight: 1
        $x_1_3 = "PSAPI.DLL" ascii //weight: 1
        $x_1_4 = "TerminateProcess" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "SHGetPathFromIDListA" ascii //weight: 1
        $x_1_7 = "360safe.exe^360tray.exe^UpdaterUI.exe^avp.exe^Mcshield.exe^VsTskMgr.exe^naPrdMgr.exe^TBMon.exe^scan32.exe^CCenter.exe^RavTask" wide //weight: 1
        $x_1_8 = "RavTask.exe^Rav.exe^RavMon.exe^RavmonD.exe^RavStub.exe^kvxp.kxp^KVMonXP.kxp^KVCenter.kxp^kvsrvxp.exe^KRegEx.exe^kavsvc.exe^UIH" wide //weight: 1
        $x_1_9 = "UIHost.exe^TrojDie.exe^FrogAgent.exe^kav.exe^kav32.exe^kavstart.exe^katmain.exe^kpfwsvc.exe^kpfw32.exe^rfwmain.exe^rfwproxy" wide //weight: 1
        $x_1_10 = "rfwproxy.exe^rfwsrv.exe^Taskmgr.exe^Regedit.exe^Msconfig.exe^360tray.exe^icesword.exe^mmc.exe^KWatch.exe^SnipeSword.exe" wide //weight: 1
        $x_1_11 = "killme.bat" wide //weight: 1
        $x_1_12 = "windir" wide //weight: 1
        $x_1_13 = "\\system32\\wscntfy.exe" wide //weight: 1
        $x_1_14 = "del %0" wide //weight: 1
        $x_1_15 = ":redel" wide //weight: 1
        $x_1_16 = "packinfo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

rule TrojanDropper_Win32_VB_DR_2147603612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DR"
        threat_id = "2147603612"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnCrYPt3D" wide //weight: 1
        $x_1_2 = "by skStud" ascii //weight: 1
        $x_1_3 = "Melt.bat" wide //weight: 1
        $x_1_4 = "Binded" ascii //weight: 1
        $x_1_5 = "RC4crypt" ascii //weight: 1
        $x_1_6 = "Temp Directory" wide //weight: 1
        $x_1_7 = "@Echo off" wide //weight: 1
        $x_1_8 = "Goto Begin" wide //weight: 1
        $x_1_9 = "AppDir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDropper_Win32_VB_GX_2147604841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.GX"
        threat_id = "2147604841"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AX:\\Computers\\Home 1.5 x\\data\\test.vbp" wide //weight: 1
        $x_1_2 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_3 = "RtlGetCompressionWorkSpaceSize" ascii //weight: 1
        $x_1_4 = "NtAllocateVirtualMemory" ascii //weight: 1
        $x_1_5 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 00 09 00 00 00 6b 65 72 6e 65 6c 33 32 00}  //weight: 1, accuracy: High
        $x_1_6 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_DW_2147621600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DW"
        threat_id = "2147621600"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 02 89 45 ?? c7 45 ac ?? ?? 40 00 c7 45 a4 08 00 00 00 c7 45 bc 65 00 00 00 c7 45 b4 02 00 00 00 8d 4d c8 51 b8 10 00 00 00 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_3 = "Wscript.Shell" wide //weight: 10
        $x_10_4 = "CUSTOM" wide //weight: 10
        $x_10_5 = "__vbaFileOpen" ascii //weight: 10
        $x_10_6 = "CopyFileA" ascii //weight: 10
        $x_1_7 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_DX_2147621797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DX"
        threat_id = "2147621797"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: High
        $x_1_2 = "Escritorio\\Stub2\\Stub.vbp" wide //weight: 1
        $x_1_3 = "Billar2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_YCE_2147622784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.YCE"
        threat_id = "2147622784"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 4d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00 [0-18] 54 00 65 00 6d 00 70 00 [0-18] 5c 00 63 00 6f 00 70 00 69 00 65 00 64 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 [0-18] 4d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_DZ_2147623750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.DZ"
        threat_id = "2147623750"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 00 00 00 54 00 65 00 6d 00 70 00 00 00 00 00 14 00 00 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 00 00 00 00 02 00 00 00 2f 00 00 00 08 00 00 00 6f 00 70 00 65 00 6e 00 00 00 00 00 0e 00 00 00 5c 00 43 00 6e 00 2e 00 62 00 61 00 74 00 00 00 08 00 00 00 44 00 65 00 6c 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 00 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 20 00 62 00 61 00 73 00 65 00 20 00 3d 00 20 00 30 00 78 00 38 00 30 00 34 00 64 00 37 00 30 00 30 00 30 00 20 00 50 00 73 00 4c 00 6f 00 61 00 64 00 65 00 64 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 4c 00 69 00 73 00 74 00 20 00 3d 00 20 00 30 00 78 00 38 00 30 00 35 00 35 00 61 00 36 00 32 00 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EA_2147624029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EA"
        threat_id = "2147624029"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a fe 64 ec fe 72 02 00 14 6c 4c ff f5 01 00 00 00 aa f5 00 01 00 00 c2 71 4c ff 00 17 6c 48 ff 6c 4c ff 04 58 ff 9d e7 aa f5 00 01 00 00 c2 71}  //weight: 1, accuracy: High
        $x_1_2 = {f5 00 00 00 00 59 80 fc 6c 90 fe f5 00 00 00 00 80 10 00 2e e8 fc 40 6c 70 fe 6c b8 fd 0a 09 00 14 00 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EB_2147624096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EB"
        threat_id = "2147624096"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = "NtUnmapViewOfSection" wide //weight: 1
        $x_1_3 = {80 0c 00 4a ec f4 02 eb fe 6e 60 ff 58 00 6c 78 ff 1b 2e 00 28 40 ff 02 00 6f 70 ff e8 80 0c 00 0b ?? ?? ?? ?? 23 3c ff 2a 23 38 ff 0a ?? ?? ?? ?? e8 0b ?? ?? ?? ?? 23 34 ff 2a 31 78 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EC_2147624175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EC"
        threat_id = "2147624175"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunpeM" ascii //weight: 1
        $x_1_2 = {72 63 34 00 41 6e 74 69 53 61 6e 64 62 6f 78 69 65}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 e8 83 c4 28 33 c0 81 fa 08 c5 bb 6c 0f 95 c0 48 68 ?? ?? 40 00 89 45 dc eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_ED_2147624176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.ED"
        threat_id = "2147624176"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "modRC4" ascii //weight: 1
        $x_1_2 = {6d 6f 64 41 6e 56 4d 00 6d 6f 64 41 6e 53 42 00 6d 6f 64 4d 65 6d 45 78 65 63}  //weight: 1, accuracy: High
        $x_1_3 = {66 8b 45 e0 66 33 45 dc 0f bf c0 50 8d 45 c0 50 e8 ?? ?? ?? ?? 8d 45 a0 50 8d 45 c0 50 8d 45 b0 50 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EE_2147624177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EE"
        threat_id = "2147624177"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VBA6.DLL" ascii //weight: 1
        $x_1_2 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 1
        $x_1_3 = {04 68 ff 6c 74 ff 04 60 ff 34 6c 60 ff f5 00 00 00 00 f5 01 00 00 00 f5 00 00 00 00 6c 70 ff 5e ?? ?? ?? ?? 71 58 ff 3c 6c 60 ff 04 74 ff fc 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EG_2147624274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EG"
        threat_id = "2147624274"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f3 00 01 c1 e7 04 58 ff 9d fb 12 fc 0d 6c 50 ff 6c 40 ff fc a0 00 0a 04 50 ff 66 ec fe db 01 00 26 f5 00 00 00 00 f5 40 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EH_2147624277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EH"
        threat_id = "2147624277"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f5 01 00 00 00 f5 00 00 00 00 f5 00 00 00 00 04 ?? ff 3a e8 fe 1c 00 fb ef f8 fe 3e ?? ff 46 ?? fe fb ef b0 fe fd fe ?? ff 04 ?? ff 34 6c ?? ff f5 00 00 00 00 f5 00 00 00 00 0a 32 00 18 00 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EI_2147624552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EI"
        threat_id = "2147624552"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 10 00 00 00 46 69 6e 64 45 78 65 63 75 74 61 62 6c 65 41 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 26 00 00 00 04 ?? ?? 0a 01 00 08 00 04 ?? ?? f5 48 00 00 00 04 ?? ?? 0a 01 00 08 00 04 ?? ?? fb ef 34 ff 28 ?? ?? 02 00 f5 01 00 00 00 6c ?? ?? f5 01 00 00 00 ae f5 02 00 00 00 b2 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_HO_2147624702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.HO"
        threat_id = "2147624702"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 2e 00 35 00 37 00 37 00 41 00 45 00 32 00 30 00 46 00 38 00 30 00 38 00 43 00 34 00 42 00 43 00 5c 00 4c 68 62 97 5c 00 e5 5d 5c 4f 3a 53 5c 00 6b 86 50 5b 5c 00 6d 00 73 00 20 00 33 00 2e 00 31 00 33 00 5c 00 2c 7b 00 4e 2a 4e 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
        $x_1_2 = "\\ttjj20.ini" wide //weight: 1
        $x_1_3 = "SonndMan.exe" wide //weight: 1
        $x_1_4 = "cmd.exe /c echo ping 127.1 -n 3 >nul 2>nul >c:\\2.bat&echo del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EK_2147625216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EK"
        threat_id = "2147625216"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 00 00 57 69 6e 45 78 65 63 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {fe 64 64 ff 93 00 3a 14 ff 11 00 28 34 ff 02 00 f5 01 00 00 00 6c 70 ff f5 01 00 00 00 ae f5 02 00 00 00 b2 aa 6c 0c 00 4d 54 ff 08 40 04 24 ff 0a 12 00 10 00 04 24 ff fb ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EL_2147625218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EL"
        threat_id = "2147625218"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Besitzer\\Desktop\\carbonaaaa" wide //weight: 1
        $x_1_2 = {43 61 6c 6c 41 50 49 62 79 4e 61 6d 65 00 00 00 53 74 61 72 74 00 00 00 52 75 6e 50 45 00 00 00 52 43 34 00 46 6f 72 6d 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_EM_2147625220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.EM"
        threat_id = "2147625220"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 08 00 00 00 2f 00 2f 00 2f 00 2f 00 00 00 00 00 06 00 00 00 6c 00 6f 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 36 00 6d 64 73 61 61 61 61 61 64 00 00 00 46 6f 72 6d 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_HP_2147625354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.HP"
        threat_id = "2147625354"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This is by TrD and D4rkDays so bow to us biatch" wide //weight: 1
        $x_1_2 = "Hello anti virus companys, this is backdoor.win32.D4rkDays" wide //weight: 1
        $x_1_3 = "76487-337-8429955-22614" wide //weight: 1
        $x_1_4 = "76487-644-3177037-23510" wide //weight: 1
        $x_1_5 = "@t SDK\\Bin\\.;C:\\P" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_ER_2147625507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.ER"
        threat_id = "2147625507"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6f 64 4d 61 69 6e 00 4d 6f 64 52 43 34 00 00 53 74 75 62 00 00 00 00 0a 00 00 00 3c 00 40 00 23 00 40 00 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 00 65 00 78 00 65 00 00 00 00 00 06 00 00 00 74 00 6d 00 70 00 00 00 1c 00 00 00 5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_HR_2147627711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.HR"
        threat_id = "2147627711"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6c 73 52 65 67 48 61 6e 64 6c 65 00 ?? ?? ?? 4d 6f 52 65 67 44 6c 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 71 71 4d 73 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2a 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 5c 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 4d 00 65 00 6e 00 75 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 73 00 5c 00 54 00 68 00 6e 00 75 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_FK_2147631743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.FK"
        threat_id = "2147631743"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "mAntiVMW" ascii //weight: 3
        $x_2_2 = "mSandBox" ascii //weight: 2
        $x_1_3 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_3_4 = "UACDisableNotify" wide //weight: 3
        $x_2_5 = "Microsoft\\Security Center" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_FL_2147631770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.FL"
        threat_id = "2147631770"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:\\\\.\\root\\default:SystemRestore" wide //weight: 1
        $x_1_2 = "SbieDll.dll" wide //weight: 1
        $x_1_3 = "taskkill /f /im" wide //weight: 1
        $x_2_4 = "\\WindowsServices.exe" wide //weight: 2
        $x_3_5 = "Sry the file you are trying to crypt is very long" wide //weight: 3
        $x_3_6 = "net stop sharedaccess" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_VB_FN_2147632022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.FN"
        threat_id = "2147632022"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\winapp.vbp" wide //weight: 1
        $x_1_2 = "UACDisableNotify" wide //weight: 1
        $x_1_3 = "crptstr" ascii //weight: 1
        $x_1_4 = "INPUTSTRING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_VB_HU_2147639754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.HU"
        threat_id = "2147639754"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OO0OOO" wide //weight: 1
        $x_1_2 = "MjkLfja" wide //weight: 1
        $x_1_3 = "e.msssm.com/tongji/" wide //weight: 1
        $x_1_4 = "hi.baidu.com/hex2bin/blog/item/ca48103cacebcf2d96ddd873.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_FY_2147640731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.FY"
        threat_id = "2147640731"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "^WQGPQGLT,FNN" wide //weight: 4
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\run" wide //weight: 2
        $x_4_3 = "R050B-DC97-43F0-8E08-F418B9.B3AE" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_HN_2147641895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.HN"
        threat_id = "2147641895"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\temp..zip" wide //weight: 2
        $x_2_2 = "Norton Antivirus Auto Protect Service" wide //weight: 2
        $x_3_3 = "Binder_Server" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_IB_2147645788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.IB"
        threat_id = "2147645788"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "nhnghjtuyytgbhtgr" wide //weight: 4
        $x_4_2 = "DECRYPTFiLE" ascii //weight: 4
        $x_3_3 = "tomaestoesparavosmaricon" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_IG_2147647563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.IG"
        threat_id = "2147647563"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Sp-Binder\\Extracter\\SpBinderExtracter.vbp" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_IJ_2147650295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.IJ"
        threat_id = "2147650295"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "COPY c:\\windows\\web\\printers\\360s.txt/b+c:\\windows\\web\\printers\\md5.txt/a c:\\windows\\web\\printers\\360sp.txt" wide //weight: 4
        $x_2_2 = "for %%i in (c d e f g h) do ( del /s /f /q /a %%i:\\*.max)" wide //weight: 2
        $x_3_3 = "dir c:\\ >c:\\windows\\web\\printers\\md5.txt" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_IN_2147652425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.IN"
        threat_id = "2147652425"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ayhost.exe" wide //weight: 1
        $x_1_2 = "bahost.exe" wide //weight: 1
        $x_1_3 = "cshost.exe" wide //weight: 1
        $x_1_4 = "djhost.exe" wide //weight: 1
        $x_1_5 = "ekhost.exe" wide //weight: 1
        $x_1_6 = "flhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VB_IP_2147654351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VB.IP"
        threat_id = "2147654351"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amhost.exe" wide //weight: 1
        $x_1_2 = "bmhost.exe" wide //weight: 1
        $x_1_3 = "cmhost.exe" wide //weight: 1
        $x_1_4 = "dmhost.exe" wide //weight: 1
        $x_1_5 = "emhost.exe" wide //weight: 1
        $x_1_6 = "fmhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

