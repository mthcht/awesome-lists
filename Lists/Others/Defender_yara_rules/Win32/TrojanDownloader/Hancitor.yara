rule TrojanDownloader_Win32_Hancitor_A_2147721373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.A!!Hancitor.gen!A"
        threat_id = "2147721373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "Hancitor: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "GUID=%I64u&BUILD=%s&INFO=%s" ascii //weight: 2
        $x_2_2 = "&IP=%s&TYPE=1&WIN=%d.%d(" ascii //weight: 2
        $x_1_3 = "zzzzzexplorer." ascii //weight: 1
        $x_1_4 = "(Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0)" ascii //weight: 1
        $x_1_5 = "api.ipify.org" ascii //weight: 1
        $x_1_6 = {f6 45 f8 44 74 1d 8b 4f 10 33 c0 85 c9 74 09 80 34 30}  //weight: 1, accuracy: High
        $x_1_7 = {72 da 5f 3b c8 73 0b 8b ff 80 34 31 ?? 41 3b c8 72 f7}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 5d 14 8a 0e 8d 95 00 fe ff ff 8b c6 80 f9}  //weight: 1, accuracy: High
        $x_1_9 = {72 26 80 3f ?? 75 21 80 7f 01 ?? 75 1b 80 7f 02 ?? 75 15 80 7f 03 ?? 75 0f}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 4d 08 80 79 01 ?? 75 ?? 0f be 01 83 c0 ?? 83 f8 ?? 77}  //weight: 1, accuracy: Low
        $x_1_11 = {8d 45 f8 50 68 11 00 28 00 ff 75 fc 68 01 68 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {8a 08 8b 55 08 80 f9 7c 74 14 84 c9 74 10 40 88 0a}  //weight: 1, accuracy: High
        $x_1_13 = {8b 45 08 80 78 01 3a 75 25 8a 00 3c 72 74 18}  //weight: 1, accuracy: High
        $x_1_14 = {83 f8 04 ba 00 31 88 84 8d 85 ?? ?? ff ff be 00 01 08 84 50 51 0f 44 f2}  //weight: 1, accuracy: Low
        $x_1_15 = {68 60 ea 00 00 ff d6 e9 ?? ?? ff ff cc 55 8b ec 8b 45 08 80 38 4d}  //weight: 1, accuracy: Low
        $x_1_16 = {85 c0 74 14 8d 4d ?? 51 ff d0 33 c0 66 83 7d ?? 09}  //weight: 1, accuracy: Low
        $x_1_17 = {8b 4d 08 6a 00 6a 01 51 8b 41 3c 8b 44 08 28 03 c1 ff d0}  //weight: 1, accuracy: High
        $x_1_18 = {30 04 31 41 3b ca 72 f0 8d 45 fc 50 8d 42 f8 50 8d 46 08 50 53 57 6a 02 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Hancitor_A_2147740667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.A!MTB"
        threat_id = "2147740667"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" ascii //weight: 1
        $x_1_2 = "Rundll32.exe %s,f1" ascii //weight: 1
        $x_1_3 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 28 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hancitor_ZZ_2147793687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.ZZ"
        threat_id = "2147793687"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b 4d 10 89 4d fc 8b 55 10 83 ea 01 89 55 10 83 7d fc 00 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb cd}  //weight: 100, accuracy: High
        $x_50_3 = {b8 01 00 00 00 c1 e0 00 8b 4d 08 0f be 14 01 83 fa 3a 75 35 8b 45 fc 0f be 08 85 c9 74 2b 8b 55 fc 0f be 02 b9 01 00 00 00 6b d1 00 8b 4d 08 0f be 14 11 3b c2 75 07 b8 01 00 00 00 eb 0d 8b 45 fc 83 c0 01 89 45 fc eb cb}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hancitor_ZY_2147793688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.ZY"
        threat_id = "2147793688"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = "ncdrleb" ascii //weight: 10
        $x_100_3 = {b8 01 00 00 00 c1 e0 00 8b 4d 08 0f be 14 01 83 fa 3a 75 35 8b 45 fc 0f be 08 85 c9 74 2b 8b 55 fc 0f be 02 b9 01 00 00 00 6b d1 00 8b 4d 08 0f be 14 11 3b c2 75 07 b8 01 00 00 00 eb 0d 8b 45 fc 83 c0 01 89 45 fc eb cb}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hancitor_ZX_2147793689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.ZX"
        threat_id = "2147793689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b8 01 00 00 00 6b c8 00 c6 81 00 50 ef 14 00 68 00 20 00 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hancitor_ARA_2147837129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hancitor.ARA!MTB"
        threat_id = "2147837129"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_6 = "krrewiaog3u4npcg.onion.to/sl/gate.php" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

