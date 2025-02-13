rule TrojanDownloader_Win32_QQHelper_A_2147803771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!A"
        threat_id = "2147803771"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 46 14 8b 4e 18 2b c7 83 c4 0c 83 f9 10 89 46 14 72 02 8b 1b c6 04 03 00 5b}  //weight: 3, accuracy: High
        $x_3_2 = {89 41 08 8b 4b 04 89 48 04 8a 53 14 8a 48 14 88 50 14 88 4b 14 80 7b 14 01}  //weight: 3, accuracy: High
        $x_3_3 = {89 41 08 8b 4b 04 89 48 04 8a 53 0e 8a 48 0e 88 50 0e 88 4b 0e 80 7b 0e 01}  //weight: 3, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_5 = "CURRENT_USER" ascii //weight: 1
        $x_1_6 = "Start Page" ascii //weight: 1
        $x_1_7 = "Explorer_Server" ascii //weight: 1
        $x_1_8 = "update.dat" ascii //weight: 1
        $x_1_9 = "WindowsUpdate" ascii //weight: 1
        $x_1_10 = "homepage" ascii //weight: 1
        $x_1_11 = "urlfolder" ascii //weight: 1
        $x_1_12 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Lamp" ascii //weight: 1
        $x_1_13 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_14 = "Kill Window Failed" ascii //weight: 1
        $x_1_15 = "Kill Window Success" ascii //weight: 1
        $x_1_16 = "-kill" ascii //weight: 1
        $x_1_17 = "Not Run" ascii //weight: 1
        $x_1_18 = "Has Run" ascii //weight: 1
        $n_50_19 = "tvguide.pps.tv" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_QQHelper_RB_2147803791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.RB"
        threat_id = "2147803791"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=E=M=b=m=" ascii //weight: 1
        $x_1_2 = "Updaterun.exe" ascii //weight: 1
        $x_1_3 = "\"%s\\rundllfromwin2000.exe\" \"%s\\wbem\\%s.dll\",Export @install" ascii //weight: 1
        $x_1_4 = "%.8X%.4X%.4X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" ascii //weight: 1
        $x_2_5 = "microsoft\\\\Direct3d\\\\dinput\\\\update" ascii //weight: 2
        $x_2_6 = ".tqzn.com/barbindsoft/barsetup.exe" ascii //weight: 2
        $x_1_7 = "\\temp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_QQHelper_C_2147803806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!C"
        threat_id = "2147803806"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?queryid=%s" ascii //weight: 1
        $x_1_2 = "InternetCloseHandle" ascii //weight: 1
        $x_1_3 = "InternetOpenA" ascii //weight: 1
        $x_1_4 = "HttpQueryInfoA" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetQueryDataAvailable" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_8 = "http://setup1.tqzn.com/barbindsoft/barsetup.exe" ascii //weight: 1
        $x_1_9 = "http://setup2.tqzn.com/barbindsoft/barsetup.exe" ascii //weight: 1
        $x_1_10 = "http://setup3.tqzn.com/barbindsoft/barsetup.exe" ascii //weight: 1
        $x_1_11 = "http://setup4.tqzn.com/barbindsoft/barsetup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_D_2147803807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!D"
        threat_id = "2147803807"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 a1 ?? ?? ?? 10 8b 0d ?? ?? ?? 10 33 c4 53 55 56 33 db 83 f9 04 89 44 24 28 57 75 08 33 c9 89 0d ?? ?? ?? 10 8b 7c 24 40 33 f6 8a 04 3e 3c 61 7c 1e 3c 7a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0 8a 92 ?? ?? ?? 10 88 94 2e ?? ?? ?? 10 eb 31 3c 41 7c 1e 3c 5a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0 8a 92 ?? ?? ?? 10 88 94 2e ?? ?? ?? 10 eb 0f 8b d1 69 d2 01 04 00 00 88 84 32 ?? ?? ?? 10 3a c3 74 09 46 81 fe 00 04 00 00 7c 9d c7 44 24 28 0f 00 00 00 89 5c 24 24 88 5c 24 14 6a ?? 68 ?? ?? ?? 10 8d 4c 24 18 89 5c 24 40 e8 ?? ?? ?? ff 8b 0d ?? ?? ?? 10 8b c1 69 c0 01 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_E_2147803808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!E"
        threat_id = "2147803808"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 20 a1 ?? ?? ?? 10 33 c5 89 45 fc a1 ?? ?? ?? 10 83 f8 04 75 07 33 c0 a3 ?? ?? ?? 10 56 57 33 f6 8b 4d 08 8a 0c 0e 80 f9 61 7c 1f 80 f9 7a 7f 1a 0f be d1 8a 92 ?? ?? ?? 10 8b f8 69 ff 01 04 00 00 88 94 37 ?? ?? ?? 10 eb 24 80 f9 41 7c 10 80 f9 5a 7f 0b 0f be d1 8a 92 ?? ?? ?? 10 eb da 8b d0 69 d2 01 04 00 00 88 8c 32 ?? ?? ?? 10 84 c9 74 09 46 81 fe 00 04 00 00 7c a5 68 ?? ?? ?? 10 8d 4d e0 e8 ?? ?? ?? ?? a1 ?? ?? ?? 10 69 c0 01 04 00 00 ff 05 ?? ?? ?? 10 6a ?? c6 84 30 ?? ?? ?? ?? ?? 6a ?? 8d 4d e0 8d b0 ?? ?? ?? 10 e8 ?? ?? ?? ?? 8b 4d fc 5f 8b c6 33 cd 5e e8 ?? ?? ?? ?? c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_F_2147803809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!F"
        threat_id = "2147803809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 20 a1 ?? ?? ?? 00 89 45 fc a1 ?? ?? ?? 00 83 f8 04 75 07 33 c0 a3 ?? ?? ?? 00 56 57 33 f6 8b 4d 08 8a 0c 0e 80 f9 61 7c 1f 80 f9 7a 7f 1a 0f be d1 8a 92 ?? ?? ?? 00 8b f8 69 ff 01 04 00 00 88 94 37 ?? ?? ?? 00 eb 24 80 f9 41 7c 10 80 f9 5a 7f 0b 0f be d1 8a 92 ?? ?? ?? 00 eb da 8b d0 69 d2 01 04 00 00 88 8c 32 ?? ?? ?? 00 84 c9 74 09 46 81 fe 00 04 00 00 7c a5 68 ?? ?? ?? 00 8d 4d e0 e8 ?? ?? ?? ?? a1 ?? ?? ?? 00 69 c0 01 04 00 00 ff 05 ?? ?? ?? 00 6a ?? c6 84 30 ?? ?? ?? ?? ?? 6a ?? 8d 4d e0 8d b0 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8b 4d fc 5f 8b c6 5e e8 ?? ?? ?? 00 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_G_2147803810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!G"
        threat_id = "2147803810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 20 a1 ?? ?? ?? 10 33 c5 89 45 fc a1 ?? ?? ?? 10 83 f8 04 75 07 33 c0 a3 ?? ?? ?? 10 56 57 33 f6 8b 4d 08 8d 14 0e 8a 0a 80 f9 61 7c 10 80 f9 7a 7f 0b 0f be c9 8a 89 ?? ?? ?? 10 eb 13 80 f9 41 7c 0e 80 f9 5a 7f 09 0f be c9 8a 89 ?? ?? ?? 10 8b f8 69 ff 01 04 00 00 88 8c 37 ?? ?? ?? 10 80 3a 00 74 09 46 81 fe 00 04 00 00 7c b3 68 ?? ?? ?? 10 8d 4d e0 e8 ?? ?? ?? ?? a1 ?? ?? ?? 10 69 c0 01 04 00 00 ff 05 ?? ?? ?? 10 6a ?? c6 84 30 ?? ?? ?? ?? ?? 6a ?? 8d 4d e0 8d b0 ?? ?? ?? 10 e8 ?? ?? ?? ?? 8b 4d fc 5f 8b c6 33 cd 5e e8 ?? ?? ?? ?? c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_H_2147803811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.gen!H"
        threat_id = "2147803811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 a1 ?? ?? ?? 10 8b 0d ?? ?? ?? 10 33 c4 53 56 33 db 83 f9 04 89 44 24 24 57 75 08 33 c9 89 0d ?? ?? ?? 10 8b 54 24 3c 33 f6 8a 04 16 3c 61 7c 0f 3c 7a 7f 0b 0f be c0 8a 80 ?? ?? ?? 10 eb 11 3c 41 7c 0d 3c 5a 7f 09 0f be c0 8a 80 ?? ?? ?? 10 8b f9 69 ff 01 04 00 00 88 84 37 ?? ?? ?? 10 38 1c 16 74 09 46 81 fe 00 04 00 00 7c bc c7 44 24 24 ?? 00 00 00 89 5c 24 20 88 5c 24 10 6a ?? 68 ?? ?? ?? 10 8d 4c 24 14 89 5c 24 3c e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? 10 8b c1 69 c0 01 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_O_2147803833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.O"
        threat_id = "2147803833"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 66 67 64 61 74 61 2e 63 66 67 00 00 00 44 6c 6c 46 75 6e 00}  //weight: 10, accuracy: High
        $x_2_2 = "\\Config\\Original\\Hook.ini" ascii //weight: 2
        $x_2_3 = "Logic\\HLib.dll" ascii //weight: 2
        $x_2_4 = "QQGameDl.exe" ascii //weight: 2
        $x_2_5 = "MainLogi.dll" ascii //weight: 2
        $x_1_6 = "Download" ascii //weight: 1
        $x_1_7 = "DownTemp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_QQHelper_T_2147803894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.T"
        threat_id = "2147803894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 bc 00 00 00 00 eb 01 ?? 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 c4 04 68 ?? ?? 40 00 8d 8d a4 fd ff ff e8 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c ?? 2e 72 69 6e 67 35 32 30 2e 6f 72 67 2f 6b 6b 6b 6b 2f 6d 6d 69 6e 73 74 61 6c 6c 2e 65 78 65 3f 71 75 65 72 79 69 64 3d}  //weight: 10, accuracy: Low
        $x_1_3 = "\\tempaq 700" ascii //weight: 1
        $x_1_4 = "SetupId" ascii //weight: 1
        $x_1_5 = "Score" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_QQHelper_D_2147803921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.D"
        threat_id = "2147803921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "16990.com" ascii //weight: 1
        $x_1_3 = "bizmd.cn/ad/ADService.asmx" ascii //weight: 1
        $x_1_4 = "96C930FD-AE94-42D0-B638-6AF8C0930FCE" ascii //weight: 1
        $x_1_5 = "B9A367EC-4DE5-402A-87CF-7DEE8ADB00E5" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "CreateServiceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_KA_2147803924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.KA"
        threat_id = "2147803924"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "NSISdl.dll" ascii //weight: 10
        $x_10_2 = "FindNextFileA" ascii //weight: 10
        $x_10_3 = "CreateDirectoryA" ascii //weight: 10
        $x_10_4 = "GetWindowsDirectoryA" ascii //weight: 10
        $x_10_5 = "SetClipboardData" ascii //weight: 10
        $x_1_6 = "qqhelper.com/bindsoft11/bindsetup.exe" ascii //weight: 1
        $x_1_7 = {71 71 68 65 6c 70 65 72 2e 63 6f 6d 2f 62 69 6e 64 73 6f 66 74 2f 62 69 6e 64 73 65 74 75 70 [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_QQHelper_Q_2147803953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.Q"
        threat_id = "2147803953"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s[%s]" ascii //weight: 1
        $x_1_2 = "%s%s=%s" ascii //weight: 1
        $x_1_3 = "%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_4 = "%.8X%.4X%.4X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" ascii //weight: 1
        $x_1_5 = "%d.%d.%d-%s" ascii //weight: 1
        $x_1_6 = "%s\\t%c.tmp" ascii //weight: 1
        $x_1_7 = "irjit.dll" ascii //weight: 1
        $x_1_8 = "ttraveler" ascii //weight: 1
        $x_1_9 = "Explorer_Server" ascii //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
        $x_1_11 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_QQHelper_RE_2147803960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/QQHelper.RE"
        threat_id = "2147803960"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "QQHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {55 8b ec 50 52 40 43 5a 58 8b 4d 08 8a 01 84 c0 74 0c 2c ?? 88 01 8a 41 01 41 84 c0 75 f4 e8}  //weight: 8, accuracy: Low
        $x_2_2 = {80 85 8a 8b 78 83 83 48 45 89 80 85 7e 4c 49 47 45 86 89 7e 46 82 82 82 82 46 84 84 80 85 8a 8b 78 83 83 45 7c 8f 7c 00}  //weight: 2, accuracy: High
        $x_2_3 = "/kkkk/mminstall.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

