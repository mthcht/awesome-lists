rule TrojanSpy_Win32_Stealer_B_2147735965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.B!bit"
        threat_id = "2147735965"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "taskkill /F /IM" wide //weight: 3
        $x_3_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_3_3 = "Select * from Win32_Process WHERE Name" wide //weight: 3
        $x_3_4 = "Content-Disposition: form-data; name=\"uploadfile\"" wide //weight: 3
        $x_2_5 = "apkikhoj.com" wide //weight: 2
        $x_2_6 = "www.exhonbanks.com" wide //weight: 2
        $x_2_7 = "seed-advertising.com" wide //weight: 2
        $x_1_8 = "--CLIPS" wide //weight: 1
        $x_1_9 = "--PARSE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Stealer_MX_2147754179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.MX!MTB"
        threat_id = "2147754179"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 03 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 3d 31 09 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f3 07 eb dd 13 81 6d ?? 52 ef 6f 62 2d f3 32 05 00 81 6d ?? 68 19 2a 14 81 45 ?? be 08 9a 76 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_RPR_2147796516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.RPR!MTB"
        threat_id = "2147796516"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d3 0f 8e ?? ff ff ff 35 00 [0-32] 8a 03 [0-16] 88 06 [0-32] 46 [0-32] 81 c3 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_MC_2147811458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.MC!MTB"
        threat_id = "2147811458"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 05 9c d7 48 00 01 00 00 00 8a 4d 10 88 0d 98 d7 48 00 83 7d 0c 00 75 4c 83 3d 94 f1 48 00 00 74 31 8b 15 90 f1 48 00 83 ea 04 89 15 90 f1 48 00 a1 90 f1 48 00 3b 05 94 f1 48 00 72 15 8b 0d 90 f1 48 00 83 39 00 74 08 8b 15 90 f1 48 00 ff 12 eb cf}  //weight: 1, accuracy: High
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "DebugBreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_MG_2147814038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.MG!MTB"
        threat_id = "2147814038"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "QSAwLjAuMw==" ascii //weight: 1
        $x_1_4 = "<password>" ascii //weight: 1
        $x_1_5 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_6 = "root\\SecurityCenter2" ascii //weight: 1
        $x_1_7 = "SELECT * FROM FirewallProduct" ascii //weight: 1
        $x_1_8 = "schtasks.exe /delete /f /tn Pirate" ascii //weight: 1
        $x_1_9 = "LockResource" ascii //weight: 1
        $x_1_10 = "CryptDestroyHash" ascii //weight: 1
        $x_1_11 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_ARA_2147836262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.ARA!MTB"
        threat_id = "2147836262"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "testtttt.ps1" ascii //weight: 2
        $x_2_2 = "Powershell.exe -executionpolicy remotesigned -File" ascii //weight: 2
        $x_2_3 = "sends the username, ip, current time, and date of the victim" ascii //weight: 2
        $x_2_4 = "Login Data" ascii //weight: 2
        $x_2_5 = "History" ascii //weight: 2
        $x_2_6 = "webhook" ascii //weight: 2
        $x_2_7 = "System_INFO.txt" ascii //weight: 2
        $x_2_8 = "netstat.txt" ascii //weight: 2
        $x_2_9 = "%username%_Capture.jpg" ascii //weight: 2
        $x_2_10 = "programms.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_ARA_2147836262_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.ARA!MTB"
        threat_id = "2147836262"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = "CreateFileW" ascii //weight: 1
        $x_1_3 = "WindDbg" ascii //weight: 1
        $x_1_4 = "ollyDbg" ascii //weight: 1
        $x_1_5 = "x64dbg" ascii //weight: 1
        $x_1_6 = "x32dbg" ascii //weight: 1
        $x_1_7 = "ObsidianGUI" ascii //weight: 1
        $x_1_8 = "ImmDbg" ascii //weight: 1
        $x_1_9 = "Zeta Debugger" ascii //weight: 1
        $x_1_10 = "Rock Debugger" ascii //weight: 1
        $x_1_11 = "PROGRAMFILES" ascii //weight: 1
        $x_1_12 = "\\VMWare\\" ascii //weight: 1
        $x_1_13 = "\\oracle\\virtualbox guest additions\\" ascii //weight: 1
        $x_2_14 = "M;i;c;r;o;s;o;f;t; ;E;n;h;a;n;c;e;d; ;R;S;A; ;a;n;d; ;A;E;S; ;C;r;y;p;t;o;g;r;a;p;h;i;c; ;P;r;o;v;i;d;e;r;" ascii //weight: 2
        $x_2_15 = "Amurncawencxrdy" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_MH_2147901639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.MH!MTB"
        threat_id = "2147901639"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SelfDelete" ascii //weight: 1
        $x_1_2 = "OverwriteMode" ascii //weight: 1
        $x_1_3 = "gidcon:cmd /c cmd < Lascia.aac" ascii //weight: 1
        $x_1_4 = "dllhost.exe" ascii //weight: 1
        $x_1_5 = "LockResource" ascii //weight: 1
        $x_1_6 = "forcenowait" wide //weight: 1
        $x_1_7 = "TEMP\\7ZipSfx.000" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Stealer_PAGL_2147937077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealer.PAGL!MTB"
        threat_id = "2147937077"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user=%d&id=%d&ip=%s&mac=%s&sysinfo=%s&url=" wide //weight: 1
        $x_1_2 = "/stat/testls" wide //weight: 1
        $x_2_3 = "SpyDll" wide //weight: 2
        $x_2_4 = "\\Hijack\\Release\\SPIFilter.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

