rule TrojanDownloader_Win32_Wixud_A_2147597869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wixud.gen!A"
        threat_id = "2147597869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wixud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 80 fa 7e 0f 85 (d2|d4) 00 00 00 a3 ?? ?? 40 00 ff 05 ?? ?? 40 00 40 3b c8 0f 84 (be|c0) 00 00 00 8a 10 80 fa 7e 75 f0 c6 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wixud_B_2147600628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wixud.gen!B"
        threat_id = "2147600628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wixud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 07 6a 00 e8 ?? ?? 00 00 bf ?? ?? 40 00 b9 ?? ?? ?? ?? a1 ?? ?? 40 00 01 44 8f fc e2 f5 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wixud_C_2147619168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wixud.gen!C"
        threat_id = "2147619168"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wixud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 70 69 6f 6e 75 f7 83 c0 05 c6 00 31 c7 45 fc 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 eb 0d 89 58 e3 66 c7 40 e7 ff 15 8b 5d d4 89 58 e9 c6 40 ed 61 c6 40 ee e9}  //weight: 1, accuracy: High
        $x_1_3 = {49 47 83 f9 00 74 50 81 3f 2e 65 78 65 74 02 eb ef}  //weight: 1, accuracy: High
        $x_1_4 = {75 f7 83 c0 ?? bb ?? ?? ?? ?? 8a 0b 88 08 8a 4b 01 88 48 01 8a 4b 02 88 48 02 8a 4b 03 88 48 03 07 00 40 81 38 (61 3d|26 61)}  //weight: 1, accuracy: Low
        $x_1_5 = "encriptstartstr!" ascii //weight: 1
        $x_1_6 = {8b 45 0c c7 00 47 45 54 20 6a 04 ff 75 e4 e8 ?? ?? ff ff e9}  //weight: 1, accuracy: Low
        $x_1_7 = {c7 00 2e 65 78 65 b9 08 00 00 00 e8 ?? ?? ff ff 25 ff 00 00 00 ba 00 00 00 00 bb 1a 00 00 00 f7 f3 8b c2 83 c0 61 8d 5d d8 88 44 0b ff e2 dc}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 00 3d 4e 45 57 20 0f 85 ?? ?? 00 00 c7 45 b4 00 00 00 00 8b 45 dc e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

