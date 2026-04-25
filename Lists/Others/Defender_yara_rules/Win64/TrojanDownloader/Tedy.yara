rule TrojanDownloader_Win64_Tedy_NITA_2147941020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.NITA!MTB"
        threat_id = "2147941020"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 ff 15 70 e5 1d 00 48 8b f8 48 85 c0 74 14 8b d5 48 8b c8 ff 15 8d e5 1d 00 48 8b cf ff 15 24 e5 1d 00 48 83 7b 18 07 4c 8b c3 76 03 4c 8b 03 48 8d 15 78 7b 23 00 48 8d 8c 24 f0 02 00 00 e8 b3 f0 ff ff 48 8d 84 24 f0 02 00 00 c7 44 24 30 70 00 00 00 48 8d 4c 24 30 48 89 44 24 50 c7 44 24 34 40 00 00 00 4c 89 74 24 38 4c 89 7c 24 40 4c 89 64 24 48 4c 89 74 24 58 44 89 74 24 60 ff 15 0a e6 1d 00 85 c0}  //weight: 2, accuracy: High
        $x_2_2 = {4c 8d 3d 3f 7c 23 00 4c 8d 25 78 7c 23 00 33 d2 b9 02 00 00 00 41 8b f6 ff 15 f8 e5 1d 00 48 8b f8 48 83 f8 ff 0f 84 47 01 00 00 48 8d 94 24 b0 00 00 00 c7 84 24 b0 00 00 00 38 02 00 00 48 8b c8 ff 15 af e5 1d 00 85 c0 0f 84 1a 01 00 00 48 83 7b 18 07 48 8b d3 76 03 48 8b 13 48 8d 8c 24 dc 00 00 00 e8 55 ab 1a 00 85 c0 74 17 48 8d 94 24 b0 00 00 00 48 8b cf ff 15 80 e5 1d 00 85 c0 75 cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_CP_2147961387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.CP!MTB"
        threat_id = "2147961387"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://files.catbox.moe/" ascii //weight: 2
        $x_2_2 = "Stop Internet" ascii //weight: 2
        $x_2_3 = "netsh advfirewall firewall delete rule name=all program=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_AHB_2147961992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.AHB!MTB"
        threat_id = "2147961992"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {c7 45 1c be da 6c 12 c7 45 20 ab f3 b1 3a c7 45 24 7a 90 d1 07 66 c7 45 28 19 00}  //weight: 30, accuracy: High
        $x_20_2 = {0f b6 cb 80 e1 ?? c0 e1 ?? 41 b9 ?? ?? ?? ?? 41 d3 e9 44 32 4c 1c 30 0f be c3 6b c8 ?? 44 32 c9 49 3b d0 73}  //weight: 20, accuracy: Low
        $x_10_3 = "sc stop AA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_CQ_2147964881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.CQ!MTB"
        threat_id = "2147964881"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Desactivado Internet!" ascii //weight: 2
        $x_2_2 = "Activado Internet!" ascii //weight: 2
        $x_2_3 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 [0-15] 22 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 62 6c 6f 63 6b 20 70 72 6f 67 72 61 6d 3d}  //weight: 2, accuracy: Low
        $x_2_4 = "netsh advfirewall firewall delete rule name=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_SX_2147965140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.SX!MTB"
        threat_id = "2147965140"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f 29 84 24 90 00 00 00 33 c0 c7 84 24 a4 00 00 00 00 00 00 00 0f 10 06 0f 11 84 24 90 00 00 00 f3 0f 7e 46 10 66 0f d6 84 24 a0 00 00 00 c7 46 10 00 00 00 00 c7 46 14 07 00 00 00 66 89 06}  //weight: 20, accuracy: High
        $x_5_2 = "\\ZhiMaSkin360.exe" ascii //weight: 5
        $x_5_3 = "ZhiMaUpdate.dll" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_AHA_2147967192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.AHA!MTB"
        threat_id = "2147967192"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath" ascii //weight: 30
        $x_20_2 = "Collects Crypto Airdrops." ascii //weight: 20
        $x_10_3 = "Brute Force of Forgotten" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Tedy_KK_2147967752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tedy.KK!MTB"
        threat_id = "2147967752"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 48 20 0f 10 00 0f 10 48 10 48 c7 c0 ff ff ff ff 0f 11 02 0f 11 4a 10 48 89 4a 20 48 8d 4c 24 40}  //weight: 20, accuracy: High
        $x_10_2 = "//45.64.52.242:1111/.woff" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

