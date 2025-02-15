rule TrojanDownloader_Win32_Tiny_BA_2147598705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.BA"
        threat_id = "2147598705"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://members.lycos.co.uk/qalbhamad/setup.exe " ascii //weight: 1
        $x_5_2 = "C:\\dos.pif......" ascii //weight: 5
        $x_5_3 = "WinExec" ascii //weight: 5
        $x_5_4 = "URLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_BB_2147598706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.BB"
        threat_id = "2147598706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://e.thec.cn/wg369/mm.exe" wide //weight: 1
        $x_5_2 = "c:\\c.exe" wide //weight: 5
        $x_5_3 = "WinExec" ascii //weight: 5
        $x_5_4 = "URLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GU_2147600077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GU"
        threat_id = "2147600077"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mozilla/5.0" ascii //weight: 1
        $x_1_2 = "PermissionDlg" ascii //weight: 1
        $x_1_3 = "Warning: Components Have Changed" ascii //weight: 1
        $x_1_4 = "Hidden Process Requests Network Access" ascii //weight: 1
        $x_1_5 = "Windows Security Alert" ascii //weight: 1
        $x_1_6 = "Allow all activities for this application" ascii //weight: 1
        $x_1_7 = "Create rule for %s" ascii //weight: 1
        $x_1_8 = "AnVir Task Manager" ascii //weight: 1
        $x_1_9 = "win32.exe" ascii //weight: 1
        $x_1_10 = {43 3a 5c 54 45 4d 50 5c 73 76 63 68 [0-1] 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GV_2147600113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GV"
        threat_id = "2147600113"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SEC Downloader" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "/c del" ascii //weight: 1
        $x_5_4 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ?? ?? ?? ?? ?? 6a 00 ff 15 ?? 12 14 13 c7 05 ?? 15 14 13 07 00 01 00 68 ?? 15 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 a1 ?? ?? 14 13 a3 ?? 13 14 13 6a 00 68 ?? 01 00 00 68 ?? 11 14 13 ff 35 ?? 13 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 8b 35 ?? 13 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 ff 35 ?? 15 14 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GW_2147600138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GW"
        threat_id = "2147600138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 31 39 35 2e 32 32 35 2e 31 37 36 2e 33 34 2f 61 64 2f ?? ?? ?? ?? 2f 61 64 76 65 72 74 6f 6f 6c 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\Unerese.exe" ascii //weight: 1
        $x_1_3 = {b8 00 30 40 00 bb 2d 30 40 00 e8 1e 00 00 00 6a 00 68 3c 30 40 00 6a 00 68 2d 30 40 00 6a 00 6a 00 e8 32 01 00 00 6a 00 e8 13 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GX_2147600630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GX"
        threat_id = "2147600630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\Internet Explorer\\SVCH0ST.EXE" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Windows Media Player\\defrenlt.wmz" ascii //weight: 1
        $x_1_3 = "easyclickplus9" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-48] 2f 6c 67 69 66 2f ?? ?? ?? ?? ?? ?? 2e 67 69 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GY_2147600891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GY"
        threat_id = "2147600891"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a6 b5 c0 d7 a0 a2 af 1d 12 32 3e 51 5e 55 79 25 97 9f 82 b8 e5 de c2 8c fa ed 52 1f 0a 25 77 52 13}  //weight: 1, accuracy: High
        $x_1_2 = {99 88 fa ee d4 c8 d4 5d 22 15}  //weight: 1, accuracy: High
        $x_1_3 = {87 af c0 c2 e8 e3 e5 07 29 29 29 51 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_J_2147604695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.J"
        threat_id = "2147604695"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f [0-16] 2e 70 68 70 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f [0-16] 2e 70 68 70 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f [0-16] 2e 70 68 70 3f 72 3d [0-4] 26 74 73 6b 3d 00 75 70 64 61 74 65 00 2e 65 78 65 00 52 75 6e 4f 6e 63 65 ?? 2e 74 5f 5f 00 52 75 6e 4f 6e 63 65 ?? 2e 74 6d 70 00 5f 73 76 63 68 6f 73 74 2e 65 78 65 00 20 2d 41 00 63 3a 5c 63 6f 6e 66 2e 6d 79}  //weight: 3, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Fuck you Spilberg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tiny_HA_2147716749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.HA!bit"
        threat_id = "2147716749"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 08 8b 54 24 04 56 8b f1 85 c0 74 30 53 57 8d 38 8b 46 04 33 db 8a 1a 8b c8 81 e1 ff 00 00 00 33 cb c1 e8 08 8b 0c 8d ?? ?? 40 00 33 c8 42 4f 89 4e 04 75 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "KH*^234se&%2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_BM_2147741576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.BM!MTB"
        threat_id = "2147741576"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 d8 31 db 31 c9 31 08 81 38 ?? ?? ?? ?? 74 ?? 83 fb 00 75 ?? 31 08 41 eb ec 81 fb 10 03 00 00 73 ?? 83 c0 04 83 c3 04 eb dc 29 d8 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_AR_2147764134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.AR!MTB"
        threat_id = "2147764134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\cs5\\cs5.exe" ascii //weight: 1
        $x_1_2 = "http://178.62.19.66/campo/v/v" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "urlmon.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_GP_2147773583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.GP!MTB"
        threat_id = "2147773583"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a [0-1] 68 [0-4] 68 [0-4] e8 [0-4] 83 [0-2] a3 [0-4] 6a [0-1] 68 [0-4] 68 [0-4] e8 [0-4] 83 [0-2] a3 [0-4] 6a [0-1] 68 [0-4] 68 [0-4] e8 [0-4] 83 [0-2] a3 [0-4] 6a [0-1] 68 [0-4] 68 [0-4] e8 [0-4] 83 [0-2] a3 [0-4] 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 8b 45 [0-1] 99 f7 f9 8b 45 [0-1] 0f be [0-2] 33 d9 8b 55 [0-1] 03 55 [0-1] 88 1a eb 3c 00 8b 4d [0-1] 03 4d [0-1] 0f be [0-1] 8b 55 [0-1] 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_QV_2147806181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.QV!MTB"
        threat_id = "2147806181"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Application Data\\worm.exe" ascii //weight: 3
        $x_3_2 = "Application Data\\rat.exe" ascii //weight: 3
        $x_3_3 = "CodingGuy" ascii //weight: 3
        $x_3_4 = "DROPPER" ascii //weight: 3
        $x_3_5 = "HelpKeywordAttribute" ascii //weight: 3
        $x_3_6 = "DownloadString" ascii //weight: 3
        $x_3_7 = "get_Network" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_CRTD_2147849809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.CRTD!MTB"
        threat_id = "2147849809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 b0 10 30 40 00 63 40 3d 8c 03 00 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_AB_2147849948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.AB!MTB"
        threat_id = "2147849948"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\install.inf" ascii //weight: 1
        $x_1_4 = "http://154.211.14.91/360.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_ARA_2147918443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.ARA!MTB"
        threat_id = "2147918443"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f4 03 4d fc 8b 95 64 ff ff ff 8b 45 fc 8a 84 05 ac fa ff ff 88 04 0a e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tiny_BB_2147933580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tiny.BB!MTB"
        threat_id = "2147933580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 31 00 34 00 37 00 2e 00 34 00 35 00 2e 00 34 00 34 00 2e 00 34 00 32 00 2f 00 62 00 6f 00 6f 00 6d 00 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 50, accuracy: Low
        $x_50_2 = {68 74 74 70 [0-1] 3a 2f 2f 31 34 37 2e 34 35 2e 34 34 2e 34 32 2f 62 6f 6f 6d 2f [0-15] 2e 65 78 65}  //weight: 50, accuracy: Low
        $x_1_3 = "System.Net" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_5_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-3] 2e 00 [0-3] 2e 00 [0-3] 2e 00 [0-15] 2f 00 62 00 6f 00 6f 00 6d 00 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_5_6 = {68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-15] 2f 62 6f 6f 6d 2f [0-15] 2e 65 78 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

