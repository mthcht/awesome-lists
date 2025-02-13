rule Backdoor_Win32_VB_UI_2147511420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.UI"
        threat_id = "2147511420"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 4e 4e 4c 13 13 54 4f 50 50 61 61 64 65 65 69 6b 6b 69 69 69 69 65 65 64 b9 f4}  //weight: 1, accuracy: High
        $x_1_2 = {2a 00 5c 00 41 00 47 00 3a 00 5c 00 41 00 59 00 4f 00 20 00 58 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 41 00 59 00 4f 00 20 00 53 00 70 00 79 00 [0-48] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 69 67 68 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 50 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_ANP_2147575270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ANP"
        threat_id = "2147575270"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "passview.dll" wide //weight: 1
        $x_1_2 = "{ScrollLock}" ascii //weight: 1
        $x_1_3 = "{PrintScreen}" wide //weight: 1
        $x_1_4 = "{ShiftLock}" wide //weight: 1
        $x_1_5 = "{AltGr}" wide //weight: 1
        $x_1_6 = "C:\\mic.wav" wide //weight: 1
        $x_1_7 = "open new Type waveaudio Alias capture" wide //weight: 1
        $x_1_8 = "\\webcam.jpg" wide //weight: 1
        $x_1_9 = "QzpcZGF0YTEucHdk" wide //weight: 1
        $x_1_10 = "tRy2H4CkM3B4By" wide //weight: 1
        $x_1_11 = "VmVyc2lvbg==" wide //weight: 1
        $x_1_12 = "SW5zdGFsbCBEaXI=" wide //weight: 1
        $x_1_13 = "RVhFLU5hbWU=" wide //weight: 1
        $x_1_14 = "TG9jYWwgSVA=" wide //weight: 1
        $x_1_15 = "QWNjZXNzIFBhc3N3b3Jk" wide //weight: 1
        $x_1_16 = "U0lOLUlQcw==" wide //weight: 1
        $x_1_17 = "UG9ydHM=" wide //weight: 1
        $x_1_18 = "T2ZmbGluZSBLZXlsb2c/" wide //weight: 1
        $x_1_19 = "TWF4aW11bSBPZmZsb2cgU2l6ZQ==" wide //weight: 1
        $x_1_20 = "VmlzaWJsZSBTZXJ2ZXI=" wide //weight: 1
        $x_1_21 = "U2VydmVyIGhXbmQ=" wide //weight: 1
        $x_1_22 = "UHJvYyBJRA==" wide //weight: 1
        $x_1_23 = "U2VydmVyIFNpemU=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_Win32_VB_ZE_2147583019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ZE"
        threat_id = "2147583019"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-64] 2f 00 56 00 2d 00 46 00 49 00 4c 00 45 00 53 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 73 00 65 00 6e 00 64 00 74 00 65 00 78 00 74 00 [0-2] 2e 00 74 00 78 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-64] 2f 00 56 00 2d 00 46 00 49 00 4c 00 45 00 53 00 2f 00 71 00 71 00 2d 00 71 00 75 00 6e 00 66 00 61 00 [0-2] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-64] 2f 00 56 00 2d 00 46 00 49 00 4c 00 45 00 53 00 2f 00 56 00 4d 00 31 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-64] 2f 00 76 00 2d 00 66 00 69 00 6c 00 65 00 73 00 2f 00 61 00 6c 00 65 00 78 00 61 00 2e 00 61 00 73 00 70 00}  //weight: 10, accuracy: Low
        $x_2_5 = "[autorun]" wide //weight: 2
        $x_2_6 = "open=IGPXE.exe" wide //weight: 2
        $x_2_7 = "shellexecute=IGPXE.exe" wide //weight: 2
        $x_2_8 = "shell\\Auto\\command=IGPXE.exe" wide //weight: 2
        $x_2_9 = "shell=Auto" wide //weight: 2
        $x_1_10 = "d:/Autorun.inf" wide //weight: 1
        $x_1_11 = "d:/IGPXE.exe" wide //weight: 1
        $x_1_12 = "\\file32.exe" wide //weight: 1
        $x_1_13 = "Rencom.exe" wide //weight: 1
        $x_1_14 = "qq_update.exe" wide //weight: 1
        $x_1_15 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_AVD_2147583055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.AVD"
        threat_id = "2147583055"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2300"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "ILFZ`MPDBM`NBDIJOF]TZTUFN]DvssfouDpouspmTfu]Tfswjdft]Tibs" wide //weight: 1000
        $x_100_2 = "ve cookieler" wide //weight: 100
        $x_100_3 = "o`lfzmphhfsAhnbjm/dpn" wide //weight: 100
        $x_100_4 = "tjmjonfzfdfl" wide //weight: 100
        $x_100_5 = "]tztufn43]" wide //weight: 100
        $x_100_6 = "u43efmfuf/emm" wide //weight: 100
        $x_100_7 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_100_8 = "mailfrom" wide //weight: 100
        $x_100_9 = "RCPT TO: " wide //weight: 100
        $x_100_10 = "rcptto" wide //weight: 100
        $x_100_11 = "mailsent" wide //weight: 100
        $x_100_12 = "SUBJECT: Tarih: " wide //weight: 100
        $x_100_13 = "Nbjm!h" wide //weight: 100
        $x_100_14 = "wscript.shell" wide //weight: 100
        $x_100_15 = "Tpguxbsf]Njdsptpgu]Xjoepxt]DvssfouWfstjpo]Svo" wide //weight: 100
        $x_100_16 = "Scripting.FileSystemObject" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 13 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_CCA_2147583797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.CCA"
        threat_id = "2147583797"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ZRHUWFVH^Nihvrupfy`Zkodt{v^DuwvhpuVjvvkpna" wide //weight: 10
        $x_5_2 = "vb5chs.dll" ascii //weight: 5
        $x_5_3 = {64 75 6d 70 72 65 70 ?? 2e 64 6c 6c}  //weight: 5, accuracy: Low
        $x_3_4 = "svchost.exe" wide //weight: 3
        $x_2_5 = "netcfgw.dll" ascii //weight: 2
        $x_2_6 = "InternetOpenA" ascii //weight: 2
        $x_2_7 = "InternetReadFile" ascii //weight: 2
        $x_2_8 = "KB95842.log" wide //weight: 2
        $x_1_9 = "npkcrypt.sys" wide //weight: 1
        $x_1_10 = "npkcrypt.vxd" wide //weight: 1
        $x_1_11 = "sysldr.dll" wide //weight: 1
        $x_1_12 = "HideFileExt" wide //weight: 1
        $x_1_13 = "Program Files\\Internet Explorer\\IEXPLORE.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_ADA_2147596913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ADA"
        threat_id = "2147596913"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "DllFunctionCall" ascii //weight: 10
        $x_10_3 = {13 54 4f 50 50 61 61 64 65 65 69 6b 6b 69 69 69 69 65 65 64}  //weight: 10, accuracy: High
        $x_10_4 = {19 5a 64 65 61 50 61 61 64 65 69 69 69 69 69 69 69 65 64 64}  //weight: 10, accuracy: High
        $x_10_5 = {13 5a 4e 4e 50 50 50 61 64 65 65 69 69 69 69 69 65 65 64 61}  //weight: 10, accuracy: High
        $x_10_6 = "TMP*.tmp" wide //weight: 10
        $x_10_7 = "TMP*.jpg" wide //weight: 10
        $x_1_8 = {3a 00 5c 00 41 00 59 00 4f 00 20 00 58 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 41 00 59 00 4f 00 20 00 53 00 70 00 79 00 20 00 34 00 33 00 5c 00 [0-48] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_WZ_2147598476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.WZ"
        threat_id = "2147598476"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.shark-project.net" wide //weight: 1
        $x_1_2 = "blacklist" wide //weight: 1
        $x_1_3 = "whatdonow" wide //weight: 1
        $x_1_4 = "*pstorage.shark" wide //weight: 1
        $x_1_5 = "*messenger.shark" wide //weight: 1
        $x_1_6 = "*mail.shark" wide //weight: 1
        $x_1_7 = "*firefox.shark" wide //weight: 1
        $x_1_8 = "*steam.shark" wide //weight: 1
        $x_1_9 = "privmsg" wide //weight: 1
        $x_1_10 = "killproc" wide //weight: 1
        $x_1_11 = "ServicesActive" wide //weight: 1
        $x_1_12 = "wscript.shell" wide //weight: 1
        $x_1_13 = "regsvr32 /s /u" wide //weight: 1
        $x_1_14 = "MSWinsockLib.Winsock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_ACF_2147601665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ACF"
        threat_id = "2147601665"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "142"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft Corporation" ascii //weight: 10
        $x_10_2 = "C:\\Program Files\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_3 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" wide //weight: 10
        $x_10_4 = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" wide //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 10
        $x_10_6 = "Antivirus Program" wide //weight: 10
        $x_10_7 = "Antivirus Schedule" wide //weight: 10
        $x_10_8 = "Antivirus Update" wide //weight: 10
        $x_10_9 = "AutoRun" wide //weight: 10
        $x_10_10 = "SFCDisable" wide //weight: 10
        $x_10_11 = "DisableRegistryTools" wide //weight: 10
        $x_10_12 = "DisableTaskMgr" wide //weight: 10
        $x_10_13 = "\\SystemFileProtection" wide //weight: 10
        $x_10_14 = "D:\\Majnun\\Majnun A\\Majnun.vbp" wide //weight: 10
        $x_2_15 = "echo off|" wide //weight: 2
        $x_2_16 = "ShowSuperHidden" wide //weight: 2
        $x_1_17 = "New Folder.exe" wide //weight: 1
        $x_1_18 = "comfile\\shell\\open\\command" wide //weight: 1
        $x_1_19 = "piffile\\shell\\open\\command" wide //weight: 1
        $x_1_20 = "scrfile\\shell\\open\\command" wide //weight: 1
        $x_1_21 = "regfile\\shell\\open\\command" wide //weight: 1
        $x_1_22 = "inffile\\shell\\Install\\command" wide //weight: 1
        $x_1_23 = "batfile\\shell\\open\\command" wide //weight: 1
        $x_1_24 = "Windows Configuration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_10_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((14 of ($x_10_*) and 2 of ($x_1_*))) or
            ((14 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_AFA_2147602199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.AFA"
        threat_id = "2147602199"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LoadEXE" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_4 = "Falha Na Mem" wide //weight: 10
        $x_10_5 = "\\LoardR0x\\System NT.vbp" wide //weight: 10
        $x_10_6 = "http://www.mindcrash.it/upload/galleriafotografica" wide //weight: 10
        $x_1_7 = "Video.exe" wide //weight: 1
        $x_1_8 = "\\system32\\Msn.exe" wide //weight: 1
        $x_1_9 = "\\system32\\svhootss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_AFB_2147602204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.AFB"
        threat_id = "2147602204"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "\\inf\\lsass.exe" wide //weight: 1
        $x_1_3 = "http://www.up.com.jo/gov/lsass.exe" wide //weight: 1
        $x_1_4 = "\\MSLoad.VB.Keylogger.Project\\DOWN.vbp" wide //weight: 1
        $x_1_5 = "microsoft Corporation. Todos os direitos reservados." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_UH_2147602319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.UH"
        threat_id = "2147602319"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 93 06 00 00 00 65 00 78 00 65 00 [0-16] ?? 00 ?? 00 2e 00 65 00 78 00 65 00 00 00 00 00 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {2a 00 5c 00 41 00 47 00 3a 00 5c 00 41 00 59 00 4f 00 20 00 58 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 41 00 59 00 4f 00 20 00 53 00 70 00 79 00 [0-48] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 6c 73 00 74 69 00 00 74 69 67 68 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_ANS_2147602353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ANS"
        threat_id = "2147602353"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Visual Basic\\X-R Host Boot\\server" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_3 = "Explorer.exe C:\\WINDOWS\\Config\\csrss.exe" wide //weight: 1
        $x_1_4 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_5 = "xbox-revenge.com" wide //weight: 1
        $x_1_6 = "supdate.exe" wide //weight: 1
        $x_1_7 = "PORTFLOOD-" wide //weight: 1
        $x_1_8 = "cAppHider" ascii //weight: 1
        $x_1_9 = "HideApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_ANT_2147602399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ANT"
        threat_id = "2147602399"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\XP" wide //weight: 1
        $x_1_2 = "PUT C:\\WINDOWS\\system32\\system32.txt Logs.txt" wide //weight: 1
        $x_1_3 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_4 = "WScript.Shell" wide //weight: 1
        $x_1_5 = "RegWrite" wide //weight: 1
        $x_1_6 = "Kaynak Kod\\Visual Basic\\Proje" wide //weight: 1
        $x_1_7 = "Desktop\\CWSpeciaL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_CCJ_2147602435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.CCJ"
        threat_id = "2147602435"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck the one who is trying to Crack this Application :D                     _From B56mx !" ascii //weight: 1
        $x_1_2 = "fuck ya boy :))" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\system32\\MSVBVM60.DLL\\3" ascii //weight: 1
        $x_1_4 = "sysver.exe;sysinfo.exe;syslnfo.exe;syschost.exe;netcmd.exe;netconfig.exe;ypager.exe" wide //weight: 1
        $x_1_5 = "{523702KJY0-YKN5OK-D1KOW-F49T8-TVUI81RWM141}" wide //weight: 1
        $x_1_6 = "{312G02HJL0-QTM7DH-A4Y08-NEDF4-SJLY23I4Z101}" wide //weight: 1
        $x_1_7 = "\\TMP1001.tmp" wide //weight: 1
        $x_1_8 = "9660.TMP" wide //weight: 1
        $x_1_9 = "SOFTWARE\\KasperskyLab" wide //weight: 1
        $x_1_10 = "net localgroup /ADD Administrators " wide //weight: 1
        $x_1_11 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 00 00 42 00 00 00 73 00 68 00 69 00 6d 00 67 00 76 00 77 00 2e 00 64 00 6c 00 6c 00 2c 00 49 00 6d 00 61 00 67 00 65 00 56 00 69 00 65 00 77 00 5f 00 46 00 75 00 6c 00 6c 00 73 00 63 00 72 00 65 00 65 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_Win32_VB_UL_2147602436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.UL"
        threat_id = "2147602436"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 41 00 59 00 4f 00 20 00 58 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 41 00 59 00 4f 00 [0-80] 5c 00 41 00 59 00 4f 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_2 = {42 00 35 00 36 00 6d 00 78 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 43 00 6f 00 6d 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = ">Yahoo! ID : <" wide //weight: 1
        $x_1_4 = {63 00 66 00 67 00 20 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {46 75 63 6b 20 74 68 65 20 6f 6e 65 20 77 68 6f 20 69 73 20 74 72 79 69 6e 67 20 74 6f 20 43 72 61 63 6b 20 74 68 69 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 3a 44 00}  //weight: 2, accuracy: High
        $x_1_6 = "Sign In;*Connect*;*Internet Explorer*" ascii //weight: 1
        $x_1_7 = "TOPPaadeeikkiiiieed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_CCL_2147606114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.CCL"
        threat_id = "2147606114"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 10 8b ?? ?? 8b d4 b9 08 00 00 00 89 4d ?? 89 45 ?? 89 0a 8b 4d ?? 6a 01 6a 43 89 4a 04 8b ?? ?? 89 42 08 8b 45 ?? 89 42 0c ff 91 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "Black Dream" ascii //weight: 1
        $x_1_3 = "KeyloggerTimer" ascii //weight: 1
        $x_1_4 = "Black Dream\\Server\\Server.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_E_2147609416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.E"
        threat_id = "2147609416"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ISubclassingSink" ascii //weight: 10
        $x_10_2 = "bytMessage" ascii //weight: 10
        $x_10_3 = "bytPassword" ascii //weight: 10
        $x_10_4 = "\\live.exe K" wide //weight: 10
        $x_2_5 = "\\live.exe EU" wide //weight: 2
        $x_2_6 = "\\live.exe S" wide //weight: 2
        $x_2_7 = "recebe_bytes_sniffados" ascii //weight: 2
        $x_1_8 = "WSAAsyncGetServByPort" ascii //weight: 1
        $x_1_9 = "WSAAsyncGetProtoByNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_U_2147609457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.U"
        threat_id = "2147609457"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\Programming\\Charon\\Client\\" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Charon" wide //weight: 1
        $x_1_3 = "\\Data\\Settings.ini" wide //weight: 1
        $x_1_4 = "\\regsvr32.exe /s " wide //weight: 1
        $x_1_5 = "Charon.ucSysTray" ascii //weight: 1
        $x_1_6 = "frmRemote_Script" ascii //weight: 1
        $x_1_7 = "mnuServer_Remove" ascii //weight: 1
        $x_1_8 = "PingMaster" ascii //weight: 1
        $x_1_9 = "frmWebcam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_AE_2147610256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.AE"
        threat_id = "2147610256"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RemoteHostIP" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "\\Messenger\\msmsgs.exe" ascii //weight: 10
        $x_10_4 = "\\Hugo Tools\\DRONES\\Proyecto1.vbp" wide //weight: 10
        $x_1_5 = "JOIN" wide //weight: 1
        $x_1_6 = "USER" wide //weight: 1
        $x_1_7 = "NICK" wide //weight: 1
        $x_1_8 = "#hugomixer" wide //weight: 1
        $x_1_9 = "set dns*" wide //weight: 1
        $x_1_10 = "cmd.exe /c netsh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_XY_2147619591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.XY"
        threat_id = "2147619591"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Users\\Jatz0r\\Desktop\\jajajaja\\anarko\\DRONES 3.0.b\\Proyecto1.vbp" wide //weight: 1
        $x_1_2 = "#pinkz0r" wide //weight: 1
        $x_1_3 = "cmd.exe /c netsh exec C:/WINDOWS/lala2.txt" wide //weight: 1
        $x_1_4 = "*** Conexion establecida." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_HO_2147624688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.HO"
        threat_id = "2147624688"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 00 00 53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 00 00 00 10 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {fe 64 64 ff 93 00 3a ?? ?? ?? ?? 28 34 ff 02 00 f5 01 00 00 00 6c 70 ff f5 01 00 00 00 ae f5 02 00 00 00 b2 aa 6c 0c 00 4d 54 ff 08 40 04 24 ff 0a 09 00 10 00 04 24 ff fb ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_ZA_2147625411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.ZA"
        threat_id = "2147625411"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\LuisCarlos\\Escritorio\\Proyectos visual basic 6.0\\Mi troyano\\BIOHAZARD 3.0\\Remote Explorer(1)\\Server\\Server.vbp" wide //weight: 5
        $x_1_2 = "vb4projectVb.Socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_QZ_2147630800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.QZ"
        threat_id = "2147630800"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHEmptyRecycleBinA" ascii //weight: 1
        $x_1_2 = "Bot Connected" wide //weight: 1
        $x_1_3 = "UDP Attack Running!" wide //weight: 1
        $x_1_4 = "autorun" wide //weight: 1
        $x_1_5 = "openmessanger" wide //weight: 1
        $x_1_6 = "\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1" wide //weight: 1
        $x_1_7 = "\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_VB_KN_2147630844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.KN"
        threat_id = "2147630844"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\Documents and Settings\\Administrator\\Desktop\\Indetectables Krypter\\demonio666vip" wide //weight: 1
        $x_1_2 = "Indetectables.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_KQ_2147631975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.KQ"
        threat_id = "2147631975"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sckServer_Connect" ascii //weight: 2
        $x_2_2 = "Select * from AntiVirusProduct" wide //weight: 2
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "SeShutdownPrivilege" wide //weight: 1
        $x_2_5 = "tmrOFFKeys" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_WO_2147634133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.WO"
        threat_id = "2147634133"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#server.exe|D|Memory Execute|%thisexe%#FileInfo.who|T|Extract File Only|None Inject" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskmgr" wide //weight: 1
        $x_1_3 = "Fuck You!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_KU_2147636172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.KU"
        threat_id = "2147636172"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\BD Kit LS - 4chan Bot" wide //weight: 3
        $x_2_2 = "CMD /C net stop mpssvc" wide //weight: 2
        $x_3_3 = "\\Install Codecs.vbs" wide //weight: 3
        $x_2_4 = "PropergateMod" ascii //weight: 2
        $x_1_5 = ":\\Recycler\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_XC_2147636489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.XC"
        threat_id = "2147636489"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Skiddie Message Flood" wide //weight: 1
        $x_1_2 = "Attempting to kill c:\\progra~1\\messenger\\msmsgs.exe!" wide //weight: 1
        $x_1_3 = "Shell_TrayWnd" wide //weight: 1
        $x_1_4 = "HDFLOOD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_LC_2147640350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.LC"
        threat_id = "2147640350"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GET /dev/zero HTTP/1.0" wide //weight: 3
        $x_3_2 = "Copying computer informartion" wide //weight: 3
        $x_3_3 = "Transferring Virus examples for analyse" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_MA_2147642946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.MA"
        threat_id = "2147642946"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "logger\\server\\Project1.vbp" wide //weight: 3
        $x_2_2 = "Windows Dizini: " wide //weight: 2
        $x_1_3 = "transferidurdur" wide //weight: 1
        $x_2_4 = "sistembilgisial" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_MS_2147647147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.MS"
        threat_id = "2147647147"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sckServer_Connect" ascii //weight: 1
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "C:\\Documents and Settings\\Abdelhamid\\My Documents\\Programmeren\\Arabain-Attacker\\Admin\\MSNMessengerAPI.tlb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_MV_2147650373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.MV"
        threat_id = "2147650373"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tmrReconectar" ascii //weight: 10
        $x_10_2 = "tmrPing" ascii //weight: 10
        $x_10_3 = "tmrCamStart" ascii //weight: 10
        $x_1_4 = "\\cam.jpg" wide //weight: 1
        $x_1_5 = "MSNMessenger" ascii //weight: 1
        $x_1_6 = "ENVIARARCHIVO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_VB_OF_2147653663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.OF"
        threat_id = "2147653663"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getpasswod:%d" ascii //weight: 1
        $x_1_2 = "xxxisterxxxvicexxocxss" ascii //weight: 1
        $x_1_3 = "xxxtware\\xxxrosoft\\xxxdows\\xxxrentVersion\\xxxServices" ascii //weight: 1
        $x_1_4 = "c:\\servidox.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_VB_OG_2147654171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.OG"
        threat_id = "2147654171"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlMoveMemory" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_2_3 = "SqUeEzEr" wide //weight: 2
        $x_2_4 = "TuvcQbui" wide //weight: 2
        $x_3_5 = "Tpguxbsf]Njdsptpgu]Bdujwf!Tfuvq]Jotubmmfe!Dpnqpofout]" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_PN_2147655728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.PN"
        threat_id = "2147655728"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://hiblog.co.kr/link.txt" wide //weight: 5
        $x_2_2 = "Navigate2" wide //weight: 2
        $x_2_3 = "keybd_event" ascii //weight: 2
        $x_1_4 = "WinHttp.WinHttpRequest.5.1" wide //weight: 1
        $x_2_5 = "ResponseBody" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_CCP_2147679293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB.CCP"
        threat_id = "2147679293"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Warnning The File Infected and is dangerous for run" wide //weight: 1
        $x_1_2 = "Data From Victim" wide //weight: 1
        $x_1_3 = "[Virus Text]" wide //weight: 1
        $x_1_4 = "W98Sck" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_VB_2147789784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/VB"
        threat_id = "2147789784"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Please check your id and password." wide //weight: 5
        $x_5_2 = "Connected! Trying to Loggin..." wide //weight: 5
        $x_5_3 = "Computer name: " wide //weight: 5
        $x_5_4 = "Is Administrator: " wide //weight: 5
        $x_5_5 = "Yahoo ID: " wide //weight: 5
        $x_1_6 = "username" wide //weight: 1
        $x_1_7 = "recvfrom" ascii //weight: 1
        $x_1_8 = "RemoteHostIP" ascii //weight: 1
        $x_1_9 = "txtkey" ascii //weight: 1
        $x_1_10 = "modSocketMaster.InitiateProcesses" wide //weight: 1
        $x_100_11 = "\\YMSG12ENCRYPT.dll" wide //weight: 100
        $x_100_12 = "*\\AC:\\Documents and Settings\\mehr\\Desktop\\sima(3)\\s\\s2\\Project1.vbp" wide //weight: 100
        $x_100_13 = "simo keylogger)" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_100_*) and 4 of ($x_5_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

