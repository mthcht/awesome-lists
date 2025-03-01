rule Trojan_Win32_Killav_6492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav"
        threat_id = "6492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You Now Hacked !!!" ascii //weight: 1
        $x_1_2 = "Net Stop Norton Antivirus Auto Protect Service" ascii //weight: 1
        $x_1_3 = "Net Stop mcshield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_CN_8053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CN"
        threat_id = "8053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Explorer.Downloader" ascii //weight: 10
        $x_10_2 = "DownloadProgress" ascii //weight: 10
        $x_10_3 = "taskkill /f /im " wide //weight: 10
        $x_10_4 = "cmd /c net stop sharedaccess" wide //weight: 10
        $x_10_5 = "http://121.14." wide //weight: 10
        $x_10_6 = "151.80/shhj/" wide //weight: 10
        $x_1_7 = "\\ad7731.exe" wide //weight: 1
        $x_1_8 = "\\IEXPLOER.EXE" wide //weight: 1
        $x_1_9 = "\\lccp.exe" wide //weight: 1
        $x_1_10 = "\\svchmest.exe" wide //weight: 1
        $x_1_11 = "\\svchmesto.exe" wide //weight: 1
        $x_1_12 = "\\svchmst.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_CO_22427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CO"
        threat_id = "22427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "J:\\gbzinho\\objfre\\i386\\Driver.pdb" ascii //weight: 1
        $x_1_2 = "ZwDeleteFile" ascii //weight: 1
        $x_1_3 = "\\Device\\HarddiskVolume1\\" wide //weight: 1
        $x_1_4 = "\\ekrnUpdate.dll" wide //weight: 1
        $x_1_5 = "\\avgupd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Killav_KB_114614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.KB"
        threat_id = "114614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 75 0c 8f 45 f8 83 65 fc 00 c7 45 e0 18 00 00 00 83 65 e4 00 83 65 e8 00 83 65 ec 00 83 65 f0 00 8d 45 f8 50 8d 45 e0 50 6a 01 8d 45 dc 50 e8 5e 00 00 00 85 c0 75 41 6a 00 ff 75 dc e8 56 00 00 00 ff 75 dc e8 54 00 00 00 eb 2d 8b 40 04 8b 50 3c 8b 7c 02 28 03 f8 8b 07 0f 20 c2 fa 52 81 e2 ff ff fe ff 0f 22 c2 66 b8 31 c0 66 ab b8 c2 08 00 00 ab 5a 0f 22 c2 fb 5f 5e c9 c2 0c 00}  //weight: 10, accuracy: High
        $x_1_2 = "bdmcon.exe" wide //weight: 1
        $x_1_3 = "bdss.exe" wide //weight: 1
        $x_1_4 = "cclaw.exe" wide //weight: 1
        $x_1_5 = "fsav32.exe" wide //weight: 1
        $x_1_6 = "fsbl.exe" wide //weight: 1
        $x_1_7 = "fsm32.exe" wide //weight: 1
        $x_1_8 = "gcasserv.exe" wide //weight: 1
        $x_1_9 = "mcshield.exe" wide //weight: 1
        $x_1_10 = "msssrv.exe" wide //weight: 1
        $x_1_11 = "nod32krn.exe" wide //weight: 1
        $x_1_12 = "zclient.exe" wide //weight: 1
        $x_1_13 = "sandbox.sys" wide //weight: 1
        $x_1_14 = "watchdog.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_KE_115672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.KE"
        threat_id = "115672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 6c 20 2f 51 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6d 63 61 66 65 65 2e 63 6f 6d 5c 2a 2e (64|65) 22}  //weight: 1, accuracy: Low
        $x_1_2 = "del /Q \"C:\\Program Files\\Symantec\\LiveUpdate\\*.exe\"" ascii //weight: 1
        $x_1_3 = {64 65 6c 20 2f 51 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 6d 61 6e 74 65 63 20 53 68 61 72 65 64 5c 2a 2e (64|65) 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Killav_FB_118717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FB"
        threat_id = "118717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4d 6f 72 70 68 65 75 73 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4b 4d 44 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4b 61 7a 61 61 20 4c 69 74 65 5c 4d 79 20 53 68 61 72 65 64 20 46 6f 6c 64 65 72 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 42 65 61 72 53 68 61 72 65 5c 53 68 61 72 65 64 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_5 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 45 64 6f 6e 6b 65 79 32 30 30 30 5c 49 6e 63 6f 6d 69 6e 67 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_6 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 6d 49 52 43 5c 44 6f 77 6e 6c 6f 61 64 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_7 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 58 6f 6c 6f 58 5c 44 6f 77 6e 6c 6f 61 64 73 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_8 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 53 68 61 72 65 61 7a 61 5c 44 6f 77 6e 6c 6f 61 64 73 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_9 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 47 72 6f 6b 73 74 65 72 5c 4d 79 20 47 72 6f 6b 73 74 65 72 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_10 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4f 76 65 72 6e 65 74 5c 49 6e 63 6f 6d 69 6e 67 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_11 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 54 65 73 6c 61 5c 46 69 6c 65 73 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_12 = {63 6f 70 79 20 22 [0-15] 2e 65 78 65 22 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 52 61 70 69 67 61 74 6f 72 5c 53 68 61 72 65 5c [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_100_13 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_1_14 = "tskill \"_AVP" ascii //weight: 1
        $x_1_15 = "tskill \"AVP" ascii //weight: 1
        $x_1_16 = "tskill \"BLACKICE\"" ascii //weight: 1
        $x_1_17 = "tskill \"ESAFE\"" ascii //weight: 1
        $x_1_18 = "tskill \"F-PROT" ascii //weight: 1
        $x_1_19 = "tskill \"PAVCL\"" ascii //weight: 1
        $x_1_20 = "tskill \"RAV7" ascii //weight: 1
        $x_1_21 = "tskill \"REGEDIT.EXE" ascii //weight: 1
        $x_1_22 = "tskill \"SCAN32\"" ascii //weight: 1
        $x_1_23 = "tskill \"ZONEALARM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 15 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_EF_123696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EF"
        threat_id = "123696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_AVPCC.EXE,_AVPM,_AVPM.EXE,AckWin32,AckWin32,ACKWIN32,AckWin32.exe,AckWin32.exe," wide //weight: 1
        $x_1_2 = {41 56 4b 69 6c 6c 5f 42 79 5f 54 48 69 61 47 30 34 45 76 65 52 00 63 73 72 73 73}  //weight: 1, accuracy: High
        $x_1_3 = {00 4d 69 73 74 61 4b 69 6c 6c 65 72 35 35 30 00}  //weight: 1, accuracy: High
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_D_124866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.D"
        threat_id = "124866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\Projetos.frm\\Flame Kill\\Project1.vbp" wide //weight: 10
        $x_10_2 = "System32\\mind.bat" wide //weight: 10
        $x_1_3 = "%finaliza% /f /im tauscan.exe" ascii //weight: 1
        $x_1_4 = "%limpa%" ascii //weight: 1
        $x_1_5 = "%finaliza% /f /im trendmicro.exe" ascii //weight: 1
        $x_1_6 = "%finaliza% /f /im update.exe" ascii //weight: 1
        $x_1_7 = "%finaliza% /f /im virus.exe" ascii //weight: 1
        $x_1_8 = "%finaliza% /f /im vbust.exe" ascii //weight: 1
        $x_1_9 = "%finaliza% /f /im vsmain.exe" ascii //weight: 1
        $x_1_10 = "%finaliza% /f /im zonealarm.exe" ascii //weight: 1
        $x_10_11 = "%registro% \"HKLM\\software\\microsoft\\security center\" /v AntiVirusDisableNotify /t REG_DWORD /d 4 /f" ascii //weight: 10
        $x_10_12 = "%registro% \"HKLM\\software\\microsoft\\security center\" /v FirewallDisableNotify /t REG_DWORD /d 4 /f" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_F_125231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.F"
        threat_id = "125231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "rrorista morto oooooo USHAuuh" ascii //weight: 10
        $x_10_3 = "swflash.inf" ascii //weight: 10
        $x_10_4 = "FrmFrwall" ascii //weight: 10
        $x_10_5 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_6 = "FP_AX_CAB_INSTALLER.exe" ascii //weight: 10
        $x_1_7 = "avast" ascii //weight: 1
        $x_1_8 = "nod32" ascii //weight: 1
        $x_1_9 = "mcafee" ascii //weight: 1
        $x_1_10 = "spyware" ascii //weight: 1
        $x_1_11 = "avira" ascii //weight: 1
        $x_1_12 = "kaspersky" ascii //weight: 1
        $x_1_13 = "panda" ascii //weight: 1
        $x_1_14 = "symantec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_C_127597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.gen!C"
        threat_id = "127597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 09 00 00 00 64 69 73 61 62 6c 65 46 57 00 00 00 ff ff ff ff 06 00 00 00 6b 69 6c 6c 41 76 00 00 ff ff ff ff 06 00 00 00 64 77 46 69}  //weight: 1, accuracy: High
        $x_1_2 = {74 72 75 65 00 00 00 00 ff ff ff ff 07 00 00 00 66 77 6b 2e 62 61 74 00 55 8b ec 33 c0 55 68 8d}  //weight: 1, accuracy: High
        $x_1_3 = {0c 00 00 00 4e 41 56 41 50 57 33 32 2e 45 58 45}  //weight: 1, accuracy: High
        $x_1_4 = {0c 00 00 00 49 43 53 55 50 50 4e 54 2e 45 58 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_CZ_132415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CZ"
        threat_id = "132415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322; .NET CLR 1.0.3705)" ascii //weight: 1
        $x_1_2 = "svchost.dll" ascii //weight: 1
        $x_1_3 = "Kill360Box" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\%s" wide //weight: 1
        $x_1_5 = "Stop360 Error!" wide //weight: 1
        $x_1_6 = "SOFTWARE\\360Safe\\safemon" wide //weight: 1
        $x_1_7 = "SYSTEM\\ControlSet003\\Services\\BITS\\Parameters" wide //weight: 1
        $x_1_8 = "360tray.exe" wide //weight: 1
        $x_1_9 = "safeboxTray.exe" wide //weight: 1
        $x_1_10 = "\\bits.dll" wide //weight: 1
        $x_1_11 = "[TAB]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_P_133111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.P"
        threat_id = "133111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 50 50 50 50 68 04 80 22 00 ff 75 f8 ff 15 ?? ?? ?? ?? 60 b8 01 00 00 00 61 ff ?? ?? e8 ?? ?? ?? ?? 59 50 6a 00 6a 01 ff 15 ?? ?? ?? ?? 6a 00 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_DD_134055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DD"
        threat_id = "134055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TerminateProcess" ascii //weight: 1
        $x_1_2 = "\\Windows\\CurrentVersion\\policies\\Explorer\\Run\\" ascii //weight: 1
        $x_1_3 = "\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii //weight: 1
        $x_1_4 = {5c 44 65 62 75 67 67 65 72 00 00 00 ff ff ff ff 07 00 00 00 6e 74 73 64 20 2d 64}  //weight: 1, accuracy: High
        $x_1_5 = {72 61 76 6d 6f 6e 2e 65 78 65 00 00 ff ff ff ff 0b 00 00 00 72 61 76 6d 6f 6e 64 2e 65 78 65 00 ff ff ff ff 0b 00 00 00 72 61 76 74 61 73 6b 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_X_135874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.X"
        threat_id = "135874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft Visual Studio\\VB" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "download_progress" ascii //weight: 10
        $x_10_4 = "taskkill /f /im " wide //weight: 10
        $x_1_5 = "cmd /c net stop sharedaccess" wide //weight: 1
        $x_1_6 = "go.cn/fd/fd5/fd" wide //weight: 1
        $x_1_7 = "http://gg.pw" wide //weight: 1
        $x_1_8 = "C:\\WINDOWS\\Fonts\\IEXPLORER.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_CK_137139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CK"
        threat_id = "137139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b6 af b7 c0 d3 f9 00 00 d0 c7 d6 f7 00 00 00 00 c8 f0}  //weight: 100, accuracy: High
        $x_100_2 = {b6 af b7 c0 d3 f9 00 00 c8 f0 d0 c7 d6 f7}  //weight: 100, accuracy: High
        $x_10_3 = "SetCursorPos" ascii //weight: 10
        $x_10_4 = "EnumChildWindows" ascii //weight: 10
        $x_10_5 = "FindWindowExA" ascii //weight: 10
        $x_10_6 = "NotifyWnd" ascii //weight: 10
        $x_10_7 = "SetTimer" ascii //weight: 10
        $x_10_8 = {d7 dc ca c7 d4 ca d0 ed}  //weight: 10, accuracy: High
        $x_10_9 = {b7 c5 b9 fd}  //weight: 10, accuracy: High
        $x_10_10 = {bc d3 c8 eb d0 c5 c8 ce b2 e5 bc fe c1 d0 b1 ed}  //weight: 10, accuracy: High
        $x_1_11 = "biaoji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_CL_137140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CL"
        threat_id = "137140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Pack.vbp" wide //weight: 5
        $x_1_2 = "avp.exe" wide //weight: 1
        $x_1_3 = "Ravmon.exe" wide //weight: 1
        $x_10_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 00 00 10 00 00 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 00 00 00 00 10 00 00 00 49 00 46 00 45 00 4f 00 46 00 49 00 4c 00 45 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_CM_137141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.CM"
        threat_id = "137141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 59 53 54 45 4d 00 00 61 76 70 2e 65 78 65 00 54 45 53 54 5f 45 56 45 4e 54}  //weight: 5, accuracy: High
        $x_5_2 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00 53 00 59 00 53 00 54 00 45 00 4d 00 00 00 00 00 54 00 45 00 53 00 54 00 5f 00 45 00 56 00 45 00 4e 00 54 00}  //weight: 5, accuracy: High
        $x_10_3 = "BaseNamedObjects\\6953EA60-8D5F-4529-8710-42F8ED3E8CDA" wide //weight: 10
        $x_10_4 = "DuplicateHandle" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_AO_137983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.AO"
        threat_id = "137983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 53 6a 04 8d ?? ?? 51 68 08 20 22 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 73 5c 36 39 35 33 45 41 36 30 2d 38 44 35 46 2d 34 35 32 39 2d 38 37 31 30 2d 34 32 46 38 45 44 33 45 38 43 44 41 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {61 76 70 2e 65 78 65 00 5c 5c 2e 5c 4d 61 67 69 63 52 63 31 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_AV_138058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.AV"
        threat_id = "138058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 50 ff d3 8b 3d ?? ?? 40 00 68 88 13 00 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd /c taskkill /im avp.exe /f" ascii //weight: 1
        $x_1_3 = "cmd /c cacls C:\\WINDOWS\\SYSTEM32 /e /p everyone:f" ascii //weight: 1
        $x_1_4 = "cmd /c sc config ekrn start= disabled" ascii //weight: 1
        $x_1_5 = "cmd /c taskkill /im ekrn.exe" ascii //weight: 1
        $x_1_6 = "cmd /c taskkill /im egui.exe" ascii //weight: 1
        $x_1_7 = "cmd /c taskkill /im ScanFrm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_BS_139322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.BS"
        threat_id = "139322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 53 53 8d 45 ?? 6a 04 50 68 4b e1 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 51 04 8d 41 08 89 45 08 89 5d ?? 8d 42 f8 89 5d fc d1 e8 89 45 ?? 74 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_BS_139322_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.BS"
        threat_id = "139322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c taskkill /im scanfrm.exe" ascii //weight: 1
        $x_1_2 = "cmd /c cacls c:\\windows\\system32 /e /p everyone:f" ascii //weight: 1
        $x_1_3 = "cmd /c sc config ekrn start= disabled" ascii //weight: 1
        $x_1_4 = "cmd /c taskkill /im ekrn.exe" ascii //weight: 1
        $x_1_5 = "cmd /c taskkill /im egui.exe" ascii //weight: 1
        $x_1_6 = "cmd /c taskkill /im avp.exe /f" ascii //weight: 1
        $x_1_7 = {6a 00 50 ff d3 68 88 13 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_BY_140991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.BY"
        threat_id = "140991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 10 27 00 00 0f 82 ?? ?? 00 00 3d c0 ff 01 00 0f 87 ?? ?? 00 00 a1 ?? ?? 40 00 3d 10 27 00 00 0f 82 ?? ?? 00 00 3d c0 ff 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {be c8 62 2b 7a ba 4a e8 93 df eb 03}  //weight: 1, accuracy: High
        $x_1_3 = {8b 32 3b 31 75 12 83 e8 04 83 c1 04 83 c2 04 83 f8 04 73 ec}  //weight: 1, accuracy: High
        $x_1_4 = {8a 08 83 c0 01 84 c9 75 f7 2b c2 3d 8c 00 00 00 0f 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Killav_KM_141135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.KM"
        threat_id = "141135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 41 00 46 00 3a 00 5c 00 11 62 84 76 a2 5b 37 62 5c 00 f0 53 7e 6e 28 75 84 76 5c 00 13 4e 28 75 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
        $x_10_2 = {41 00 46 00 3a 00 5c 00 11 62 84 76 0b 7a 8f 5e 5c 00 32 00 30 00 30 00 39 00 74 5e 2a 4e ba 4e 48 72 0b 4e 7d 8f 05 80 5c 00 d8 9a 74 51 4d 4f 6e 7f 13 4e 28 75 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
        $x_10_3 = {5c 00 41 00 46 00 3a 00 5c 00 11 62 84 76 0b 7a 8f 5e 5c 00 32 00 30 00 30 00 39 00 74 5e 2a 4e ba 4e 48 72 0b 4e 7d 8f 05 80 5c 00 d8 9a 74 51 4d 4f 6e 7f 13 4e 28 75 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
        $x_10_4 = {2a 00 5c 00 41 00 46 00 3a 00 5c 00 11 62 84 76 0b 7a 8f 5e 5c 00 32 00 30 00 30 00 39 00 74 5e 2a 4e ba 4e 48 72 0b 4e 7d 8f 05 80 5c 00 05 53 4d 4f 6e 7f 13 4e 28 75 5c 00 e5 5d 0b 7a 31 00 2e 00}  //weight: 10, accuracy: High
        $x_1_5 = "safeboxtray.exe" wide //weight: 1
        $x_1_6 = "QQKav.exe" wide //weight: 1
        $x_1_7 = "KvDetect.exe" wide //weight: 1
        $x_1_8 = "Trojanwall.exe" wide //weight: 1
        $x_1_9 = "QQDoctor.exe" wide //weight: 1
        $x_1_10 = "KvfwMcl.exe" wide //weight: 1
        $x_1_11 = "TrojDie.kxp" wide //weight: 1
        $x_1_12 = "EGHOST.exe" wide //weight: 1
        $x_1_13 = "KVMonXP.kxp" wide //weight: 1
        $x_1_14 = "UIHost.exe" wide //weight: 1
        $x_1_15 = "360Safe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_DI_141710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DI"
        threat_id = "141710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c sc config ekrn start= disabled" ascii //weight: 1
        $x_1_2 = "/c taskkill.exe /im e" ascii //weight: 1
        $x_1_3 = "%s%dtest.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_DK_142699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DK"
        threat_id = "142699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f be 00 85 c0 74 ?? 8b 45 fc 0f be 00 83 f8 7c 75 06 8b 45 fc c6 00 00 8b 45 fc 40}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 00 6a 04 8d 45 ec 50 68 08 20 22 00 ff 75 08 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 8d 45 fc 50 6a 04 ff 75 10 6a 04 8d 45 0c 50 68 4b 21 22 00 ff 75 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Killav_DV_144880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DV"
        threat_id = "144880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e8 83 c2 01 89 55 e8 [0-16] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {00 61 6e 74 69 5f 61 76 ?? 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 44 61 74 61 00 52 6f 61 6d 69 6e 67 00 4d 69 63 72 6f 73 6f 66 74 [0-5] 57 69 6e 64 6f 77 73 00 25 73 5c 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_DO_145705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DO"
        threat_id = "145705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f9 61 c6 45 fa 62 c6 45 fb 6c c6 45 fc 65 c6 45 fd 64}  //weight: 1, accuracy: High
        $x_3_2 = {76 10 80 04 3e fd 57 46 e8 ?? ?? ?? 00 3b f0 59 72 f0}  //weight: 3, accuracy: Low
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_DP_146341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DP"
        threat_id = "146341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 61 6e 74 69 5f 61 76 01 00 2e 64 6c 6c 00}  //weight: 2, accuracy: Low
        $x_2_2 = {66 c7 45 ea 0f 04 66 89 7d e8 e8 ?? ?? ?? ?? 6a 32 ff 15 ?? ?? ?? ?? 6a 1c 8d 45 e4 6a 00 50 e8 ?? ?? ?? ?? 83 4d ec 02 83 c4 0c 6a 1c 8d 45 e4 50 56 89 75 e4 66 c7 45 ea 0f 04}  //weight: 2, accuracy: Low
        $x_2_3 = {00 10 6a 09 e8 ?? ?? ?? ?? 6a 09 e8 ?? ?? ?? ?? 6a 09 e8 ?? ?? ?? ?? 6a 0d e8}  //weight: 2, accuracy: Low
        $x_1_4 = {00 7a 6f 6e 65 61 6c 61 72 6d 00 00 00 7a 61 75 6e 69 6e 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 62 69 74 64 65 66 65 6e 64 65 72 00 6b 61 73 70 65 72 73 6b 79 00 00 00 63 70 65 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 61 76 67 00 6d 73 69 65 78 65 63 00 67 20 64 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 61 76 61 73 74 00 00 00 5c 53 65 74 75 70 5c 73 65 74 69 66 61 63 65 2e 64 6c 6c 22 2c 52 75 6e 53 65 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 70 6f 73 74 69 6e 73 74 61 6c 6c 00 2f 74 55 6e 49 6e 73 74 61 6c 6c 00 66 2d 73 65 63 75 72 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 6d 63 61 66 65 65 00 00 6d 63 75 6e 69 6e 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_DR_146604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DR"
        threat_id = "146604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 61 6e 74 69 5f 61 76 01 00 2e 64 6c 6c 00}  //weight: 5, accuracy: Low
        $x_5_2 = {66 c7 45 ea 0f 04}  //weight: 5, accuracy: High
        $x_4_3 = {8b 45 e8 0f be 08 85 c9 74 ?? 8b 55 e8 0f be 02 83 e8 ?? 8b 4d e8 88 01}  //weight: 4, accuracy: Low
        $x_4_4 = {8b 55 f0 8a 02 50 e8 ?? ?? ff ff 83 c4 04 0f be f0 8b 4d f4 8a 11 52 e8 ?? ?? ff ff 83 c4 04 0f be c0 3b f0 75 ?? b0 ?? b0}  //weight: 4, accuracy: Low
        $x_1_5 = {00 7a 61 75 6e 69 6e 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_2_6 = {00 5c 53 65 74 75 70 5c 73 65 74 69 66 61 63 65 2e 64 6c 6c 22 2c 52 75 6e 53 65 74 75 70}  //weight: 2, accuracy: High
        $x_1_7 = {00 2f 74 55 6e 49 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_8 = {00 6d 63 75 6e 69 6e 73 74}  //weight: 1, accuracy: High
        $x_1_9 = {00 2f 52 45 4d 4f 56 45}  //weight: 1, accuracy: High
        $x_1_10 = {00 67 20 64 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 73 6f 75 70 38 38 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 74 76 66 31 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 70 6f 73 74 69 6e 73 74 61}  //weight: 1, accuracy: High
        $x_1_14 = {00 42 75 74 74 6f 6e 00 00 41 56 47}  //weight: 1, accuracy: High
        $x_1_15 = {00 63 61 6c 6c 6d 73 69 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_DY_148399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.DY"
        threat_id = "148399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ea 33 c0 c3 0e 00 32 d1 88 90 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ea}  //weight: 2, accuracy: Low
        $x_2_2 = {74 09 81 7d 08 03 01 00 00 75 1a 68 00 80 00 00 6a 00 56 57 e8 ?? ?? ?? ?? 0b d8 81 fe 00 f0 ff 7f 73 07 eb c0}  //weight: 2, accuracy: Low
        $x_2_3 = {83 c4 08 85 c0 74 45 56 6a 00 e8 ?? ?? ?? ?? 83 c4 04 8b 35 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6}  //weight: 2, accuracy: Low
        $x_2_4 = {75 2d 8b 44 24 24 83 f8 0a 0f 84 c6 00 00 00 40 83 f8 0c 89 44 24 24 0f 8c ?? ?? ff ff 5f 5e 5d b8 01 00 00 00 5b 81 c4 74 03 00 00 c2 04 00}  //weight: 2, accuracy: Low
        $x_2_5 = {81 7d cc 08 20 22 00 74 0b 81 7d cc 0c 20 22 00 74 37 eb 73 8d 45 f0 50 8b 4d e0 8b 11 52 ff 15 ?? ?? ?? ?? 68 00 00 92 7c 8b 45 f0 50 e8 ?? ?? ?? ?? 68 00 00 93 7c 8b 4d f0 51 e8 ?? ?? ?? ?? c7 45 dc 00 00 00 00 eb 3e}  //weight: 2, accuracy: Low
        $x_2_6 = {75 20 6a 00 68 9b 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 c4 00 00 00 00 eb 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Killav_EW_148938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EW"
        threat_id = "148938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe user32.dll, LockWorkStation" ascii //weight: 1
        $x_1_2 = "del %windir%\\system32\\mrt.exe /q" ascii //weight: 1
        $x_1_3 = "NET STOP Windows Firewall" ascii //weight: 1
        $x_1_4 = "NET STOP Windows Update" ascii //weight: 1
        $x_1_5 = "taskkill /f /im msseces.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_EI_149490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EI"
        threat_id = "149490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 36 30 53 61 66 65 2e 65 78 65 00 (53 79 73 54|44 69 6b)}  //weight: 1, accuracy: Low
        $x_1_2 = "ZhuDongFangYu.exe" ascii //weight: 1
        $x_1_3 = {8a 0c 02 80 c1 ?? 88 08 40 4e 75 f4 5e c3}  //weight: 1, accuracy: Low
        $x_1_4 = {68 e0 2e 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 10 27 00 00 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Killav_EX_150700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EX"
        threat_id = "150700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d0 2b 55 b8 81 fa d0 07 00 00 72 0e}  //weight: 2, accuracy: High
        $x_3_2 = {33 c0 8b d0 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 8a 4c 0c 08}  //weight: 3, accuracy: High
        $x_2_3 = {5d 54 6a 00 6a 00 6a 0c 8d 4c 24 ?? 51 6a 09 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = {6a 0b ff 15 ?? ?? ?? ?? 8d 43 04 8b 50 08 89 15 ?? ?? ?? ?? 0f b7 48 1a 03 c1 83 c0 1c}  //weight: 1, accuracy: Low
        $x_3_5 = {33 d2 f7 f7 bf 19 00 00 00 33 d2 f7 f7 80 c2 61}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_EZ_152274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EZ"
        threat_id = "152274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Device\\MSN" wide //weight: 2
        $x_1_2 = "\\App Paths\\360Safe.exe" ascii //weight: 1
        $x_1_3 = "ZhuDongFangYu.exe" ascii //weight: 1
        $x_1_4 = "\\system\\pci.sy" ascii //weight: 1
        $x_3_5 = {52 75 6e 64 6c 6c 2e 64 6c 6c 00 62}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_EY_152276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EY"
        threat_id = "152276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de c1 eb 19 c1 e6 07 0f be d2 0b de 33 da}  //weight: 1, accuracy: High
        $x_1_2 = {75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 1, accuracy: High
        $x_2_3 = {80 c1 fd 88 8e ?? ?? ?? 10 46}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FA_152546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FA"
        threat_id = "152546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "360tray.exe" ascii //weight: 1
        $x_1_2 = "system32\\drivers\\360" ascii //weight: 1
        $x_1_3 = "\\\\.\\KillProcess" ascii //weight: 1
        $x_2_4 = {75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_FC_153230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FC"
        threat_id = "153230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 11 eb 04 3b ?? 74 41 ?? 3b ?? 0f 8e ?? ?? ff ff eb 09}  //weight: 2, accuracy: Low
        $x_1_2 = {85 c0 74 09 81 7d ?? 03 01 00 00 75 11}  //weight: 1, accuracy: Low
        $x_1_3 = "aseNamedObjects\\6953EA60-8D5F-4529-8710-42F8ED" wide //weight: 1
        $x_1_4 = "ndows\\AntiVirus.sys" ascii //weight: 1
        $x_1_5 = "rvices\\drmkaud" ascii //weight: 1
        $x_1_6 = "0KVSrvXP.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_EN_153356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EN"
        threat_id = "153356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 71 71 2e 65 78 65 00 5c 74 65 6e 63 65 6e 74 5c 00 00 00 5c 73 61 66 65 6d 6f 6e 5c 00 00 00 5c 33 36 30 73 61 66 65}  //weight: 1, accuracy: High
        $x_1_2 = {2f 63 6e 7a 7a 32 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 04 68 e8 03 00 00 ff d3 47 83 ff 05 7c c9 68 04 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_EO_153357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.EO"
        threat_id = "153357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 71 71 2e 65 78 65 00 5c 74 65 6e 63 65 6e 74 5c 00 00 00 5c 73 61 66 65 6d 6f 6e 5c 00 00 00 5c 33 36 30 73 61 66 65}  //weight: 1, accuracy: High
        $x_1_2 = "cnzz44.html" ascii //weight: 1
        $x_1_3 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? 8d 94 24 ?? ?? ?? ?? 6a 00 52 e8 ?? ?? ?? ?? 83 c4 08 83 f8 ff 74 29 68 04 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FC_153379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FC!dll"
        threat_id = "153379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If-None-Match: \"60794-12b3-e4169440\"" ascii //weight: 1
        $x_1_2 = {25 73 25 64 00 00 00 00 25 73 20 2f 73 20 2c 25 73 00 00 00 25 73 5c 25 64 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 5c 00 2a 00 00 00 00 00 25 00 73 00 2a 00 2e 00 2a}  //weight: 1, accuracy: High
        $x_1_4 = {25 64 25 6e 00 00 00 00 25 32 35 35 5b 5e 2f 3a 5d}  //weight: 1, accuracy: High
        $x_1_5 = {14 5a 01 10 00 00 00 00 2e 48 00 00 5c 62 72 70 63 73 73 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FE_153965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FE"
        threat_id = "153965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 45 00 4d 00 50 00 5c 00 41 00 56 00 2d 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 20 73 74 6f 70 20 93 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "netsh firewall set opmode mode=disable" ascii //weight: 1
        $x_1_4 = "tskill /A av*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_KV_156500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.KV"
        threat_id = "156500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 03 2b f7 99 46 f7 fe 8b c2 03 c7}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 74 07 8d 54 24 04 e9 69 08 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\R%cm%ct%cC.dll" ascii //weight: 1
        $x_1_4 = "\\_netbot\\i386\\" ascii //weight: 1
        $x_1_5 = "KiServiceLimit==%08X" ascii //weight: 1
        $x_1_6 = "\\\\.\\RiSing2008" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Killav_FE_157845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FE!dll"
        threat_id = "157845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4f d1 c1 5b 1e 00 c6 45 ?? 61 c6 45 ?? 76 c6 45 ?? 70 c6 45 ?? 2e 88 45 ?? 88 5d ?? 88 45 ?? c6 45 ?? 00 90}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 50 03 00 00 b0 73 53 88 45 ?? 88 45 ?? b0 6b b3 78 88 45 ?? 88 45 ?? b0 6c b2 2f 88 45 ?? 88 45 ?? b0 65 b1 20}  //weight: 1, accuracy: Low
        $x_1_3 = "dys1h{h" ascii //weight: 1
        $x_1_4 = "frqilj#dys#vwduw@#glvdeohg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FM_161469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FM"
        threat_id = "161469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 61 00 76 00 6d 00 6f 00 6e 00 64 00 00 00 73 00 66 00 63 00 74 00 6c 00 63 00 6f 00 6d 00 00 00 00 00 6d 00 70 00 6d 00 6f 00 6e 00 00 00 74 00 77 00 69 00 73 00 74 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e1 27 c6 45 e2 f6 c6 45 e3 36 c6 45 e4 56 c6 45 e5 37 c6 45 e6 37 c6 45 e7 33 c6 45 e8 23 c6 45 e9 64 c6 45 ea 96 c6 45 eb 27 c6 45 ec 37 c6 45 ed 47 c6 45 ee 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FN_163437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FN"
        threat_id = "163437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "keybd_event" ascii //weight: 2
        $x_2_2 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 2
        $x_2_3 = "[CapsLock]" ascii //weight: 2
        $x_2_4 = ":]%d-%d-%d  %d:%d:%d" ascii //weight: 2
        $x_2_5 = "%s\\shell\\open\\command" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_FO_163906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FO"
        threat_id = "163906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 56 47 00 6a ff 68 00 00 00 00 8d 4d 00 e8 00 00 00 00 85 c0 0f 84}  //weight: 3, accuracy: High
        $x_2_2 = {51 50 68 38 04 00 00 ff 15 ?? ?? ?? ?? 8b e8 85 ed 0f 84 ?? ?? ?? ?? 33 c0 6a 1c}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 10 74 11 83 f8 20 74 0c 83 f8 40 74 07 3d 80 00 00 00 75 ?? 8b 44 24 ?? 6a 04 68 00 30 00 00 50 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = {75 70 64 61 74 65 2e 65 78 65 00 00 41 56 49 52 41 00 00 00 61 76 67 75 70 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = "C:\\avub\\Release\\avub.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_FP_164888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FP"
        threat_id = "164888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c}  //weight: 4, accuracy: High
        $x_4_2 = {83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca}  //weight: 4, accuracy: High
        $x_1_3 = "N65sPs5jBcLuPG" ascii //weight: 1
        $x_1_4 = "N65sPsDpSdPXBcLuPJ4" ascii //weight: 1
        $x_1_5 = "N5DbON9ZQ51oRtPfP6LoBcLuPG" ascii //weight: 1
        $x_1_6 = "ONPdOsXpTdWkPNXb" ascii //weight: 1
        $x_1_7 = "ONPdOt9bRNWkPNXbCG" ascii //weight: 1
        $x_1_8 = "GLP7L6zlR69XSabkStHXR6mkPNXbCG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_FS_166887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FS"
        threat_id = "166887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "82E42502E6" ascii //weight: 1
        $x_1_2 = "82556513E6" ascii //weight: 1
        $x_1_3 = "82C404E7" ascii //weight: 1
        $x_1_4 = "8265D5E7" ascii //weight: 1
        $x_1_5 = "82A4D50373E5" ascii //weight: 1
        $x_1_6 = "8264E52203E5" ascii //weight: 1
        $x_1_7 = "F5C40522F3F380" ascii //weight: 1
        $x_1_8 = "0251302273" ascii //weight: 1
        $x_1_9 = "A5E69731E1A243BBDB" ascii //weight: 1
        $x_1_10 = "F4A6E760F0A2E39C3CE29770A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Killav_FV_169974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.FV"
        threat_id = "169974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 38 ff ff ff ba 12 00 00 00 e8 ?? ?? ?? ?? 8b 85 38 ff ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a b8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? 00 00 80 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 5d fc 85 db 74 ?? 83 eb 04 8b 1b 43 53 8b 45 fc e8 ?? ?? ?? ?? 50 6a 01 6a 00 8b 45 f8}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "AVGIDSAgent.exe" ascii //weight: 1
        $x_1_5 = "AVGIDSMonitor.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Killav_GI_172156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GI"
        threat_id = "172156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.pva" ascii //weight: 1
        $x_1_2 = "exe.nrk23don" ascii //weight: 1
        $x_1_3 = "exe.dleihscm" ascii //weight: 1
        $x_1_4 = "exe.serifvap" ascii //weight: 1
        $x_1_5 = "exe.ppacc" ascii //weight: 1
        $x_1_6 = "exe.nomtnccp" ascii //weight: 1
        $x_1_7 = "exe.23mssf" ascii //weight: 1
        $x_1_8 = "exe.tratsvak" ascii //weight: 1
        $x_1_9 = "exe.ecivresfpm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Killav_GJ_172318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GJ"
        threat_id = "172318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 e0 50 e8 ?? ?? ?? ?? 6a 04 ?? 6a 04 6a 00 68 ac dd 48 00 8b 45 e0 50 e8 ?? ?? ?? ?? 6a 04 ?? 6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 e0 50 e8 ?? ?? ?? ?? 6a 04 ?? 6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 e0 50 e8 ?? ?? ?? ?? 6a 04 ?? 6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 e0 50 e8 ?? ?? ?? ?? 6a 04 ?? 6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 e0 50 e8}  //weight: 3, accuracy: Low
        $x_3_2 = {68 02 00 00 80 e8 ?? ?? ?? ?? 85 c0 75 20 6a ?? 68 ?? ?? ?? ?? 6a 02 6a 00 68 ?? ?? ?? ?? 8b 03 50 e8 68 95 f7 ff 8b 03 50 e8 40 95 f7 ff 53 68 3f ?? 0f 00 6a 00 68 60 e2 48 00 68 02 00 00 80 e8 39 95 f7 ff 85 c0 75 20 6a ?? 68 6c e1 48 00 6a 02 6a 00 68 94 e1 48 00 8b 03 50}  //weight: 3, accuracy: Low
        $x_1_3 = "AVGcfgex.exe" ascii //weight: 1
        $x_1_4 = "AVGchsvx.exe" ascii //weight: 1
        $x_1_5 = "AVGcmgr.exe" ascii //weight: 1
        $x_1_6 = "AVGcsrvx.exe" ascii //weight: 1
        $x_1_7 = "AVGdiagex.exe" ascii //weight: 1
        $x_1_8 = "Microsoft Security Client" ascii //weight: 1
        $x_1_9 = "ConfigSecurityPolicy.exe" ascii //weight: 1
        $x_1_10 = "msseces.exe" ascii //weight: 1
        $x_1_11 = "MsseWat.dll" ascii //weight: 1
        $x_1_12 = "NortonInstaller" ascii //weight: 1
        $x_1_13 = "Hidden" ascii //weight: 1
        $x_1_14 = "HideFileExt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_GL_173031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GL"
        threat_id = "173031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "360tray;avgnt;avgaurd;avcenter;adam;AgentSvr;AntiArp;" ascii //weight: 1
        $x_1_2 = ";kissvc;kswebshield;ZhuDongFangYu;SuperKiller;" ascii //weight: 1
        $x_1_3 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 7e [0-16] 2e 74 78 74 [0-21] 4f 48 48 62 68 50 72 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 78 4d 00 00 e8 ?? ?? ?? ?? 6a 00 8d 45 ?? 50 68 78 4d 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {7c 14 46 33 d2 33 db 8a 1c 10 66 81 f3 ?? ?? 88 1c 11 42 4e 75 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Killav_GM_173382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GM"
        threat_id = "173382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7181B65483A35686A2" ascii //weight: 1
        $x_1_2 = "1D23D07CB8A2498BBB" ascii //weight: 1
        $x_1_3 = "98AA619F47EE1FC7659D4127A220B" ascii //weight: 1
        $x_1_4 = {54 68 00 04 00 00 8d 44 24 0c 50 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_GO_173648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GO"
        threat_id = "173648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe ADD \"HKLM\\Software\\Microsoft\\Security Center\"" ascii //weight: 1
        $x_1_2 = "/v AntiVirusDisableNotify /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_3 = "/v FirewallDisableNotify /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_4 = "/v UpdatesDisableNotify /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_5 = "/v AllowTSConnections /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_6 = "/v fDenyTSConnections /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_7 = "/v fAllowToGetHelp /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_GP_174583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.GP"
        threat_id = "174583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GbPlugin\\" wide //weight: 1
        $x_1_2 = {30 39 2e 3a 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 72 69 6e 63 69 70 61 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "avgnsx.exe" wide //weight: 1
        $x_1_4 = "AVGNT" wide //weight: 1
        $x_1_5 = "ServiceAfterInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_AAD_195802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.AAD"
        threat_id = "195802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 6d 70 00 53 75 70 65 72 2d 45 43 00}  //weight: 1, accuracy: High
        $x_1_3 = "TASKKILL /F /IM NaverAgent.exe /T" ascii //weight: 1
        $x_1_4 = "TASKKILL /F /IM nsvmon.npc /T" ascii //weight: 1
        $x_1_5 = "\\restart.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_AAE_199613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.AAE"
        threat_id = "199613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {47 65 74 4b 69 6c 6c 41 76 2e 64 6c 6c 00 45 78 65 63 4b 69 6c 6c 61 64 6f 72 00}  //weight: 10, accuracy: High
        $x_1_2 = "QVZHXEFWRzIwMTJcYXZndWkuZXhl" ascii //weight: 1
        $x_1_3 = "QVZHXEFWRzIwMTNcYXZnd2RzdmMuZXhl" ascii //weight: 1
        $x_1_4 = "QVZHXEFWRzIwMTI=" ascii //weight: 1
        $x_1_5 = "QXZhc3RVSS5leGU=" ascii //weight: 1
        $x_1_6 = "QXZhc3RTdmMuZXhl" ascii //weight: 1
        $x_1_7 = "QVZBU1QgU29mdHdhcmU=" ascii //weight: 1
        $x_1_8 = "QWx3aWwgU29mdHdhcmU=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_HB_204306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.HB"
        threat_id = "204306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 64 2e 25 64 2e 25 64 20 (6d|74 72 65 6e 64 6d 69 63) 20 6b 69 6c 6c 65 64}  //weight: 10, accuracy: Low
        $x_10_2 = "id=%s&data=" ascii //weight: 10
        $x_10_3 = {4e 54 46 00 25 64 2e 25 64 2e 25 64 20 25 73 00 43 72 79 70 74 64 6c 6c 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_1_4 = "187.33.1.171" ascii //weight: 1
        $x_1_5 = "91.121.16.24" ascii //weight: 1
        $x_1_6 = "198.101.241.159" ascii //weight: 1
        $x_1_7 = "91.121.55.127" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killav_HF_212903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.HF"
        threat_id = "212903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 0f be 08 85 c9 74 6d 8b 55 f8 0f be 02 83 e8 01 8b 4d f8 88 01 b0 6f b0 ff b0 f5 b0 f5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f8 83 c2 01 89 55 f8 b0 6f b0 ff b0 f5 b0 f5 b0 38 b0 70 b0 6f b0 49 b0 c0 b0 89 b0 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_HF_212903_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.HF"
        threat_id = "212903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 1d 6a ff ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? eb 03 8d 49 00 e8 ?? ?? ?? ?? 68 d0 07 00 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 2d 00 6e 00 65 00 77 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 2d 00 6e 00 6f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 2d 00 6e 00 6f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 20 00 2d 00 73 00 20 00 2d 00 70 00 68 00 73 00 76 00 63 00 20 00 2d 00 63 00 20 00 2d 00 63 00 74 00 79 00 70 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 63 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 20 00 2d 00 63 00 61 00 63 00 74 00 69 00 6f 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 2d 00 6e 00 65 00 77 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 2d 00 6e 00 6f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 2d 00 6e 00 6f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 20 00 2d 00 73 00 20 00 2d 00 70 00 68 00 73 00 76 00 63 00 20 00 2d 00 63 00 20 00 2d 00 63 00 74 00 79 00 70 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 63 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4d 00 73 00 4d 00 70 00 53 00 76 00 63 00 20 00 2d 00 63 00 61 00 63 00 74 00 69 00 6f 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_HG_213080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.HG"
        threat_id = "213080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /t /im MSASCui.exe" ascii //weight: 1
        $x_1_2 = "net stop WinDefend" ascii //weight: 1
        $x_1_3 = "sc config wuauserv start= disabled" ascii //weight: 1
        $x_1_4 = "\\Windows Defender\\security.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killav_HI_214178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killav.HI"
        threat_id = "214178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 d4 b0 98 b0 37 b0 16 b0 38 b0 b1 b0 85 8b 45 08 03 45 f8 0f be 08 83 c1 20 8b 55 08 03 55 f8 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {b0 38 b0 b1 b0 85 c7 85 a0 fe ff ff 00 00 00 00 eb 0f 8b 95 a0 fe ff ff 83 c2 01 89 95 a0 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

