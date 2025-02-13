rule TrojanDownloader_Win32_Zbot_D_2147645665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zbot.D"
        threat_id = "2147645665"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wms1" ascii //weight: 1
        $x_2_2 = {8b d3 81 e2 f0 00 00 00 c1 ea 04 83 fa 40 77 33 6a 00 68 80 00 00 00 6a 03 6a 00 8b c3 25 f0 00 00 00 c1 e8 04}  //weight: 2, accuracy: High
        $x_2_3 = {be 38 b5 41 6a 0f b7 f9 8b df 81 c3 92 3e 58 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zbot_E_2147645754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zbot.E"
        threat_id = "2147645754"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 89 65 f8 c7 45 ?? ?? 13 40 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ba ?? ?? ?? 00 b9 ?? ?? ?? 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? 00 b9 ?? ?? ?? 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 57 89 65 f4 c7 45 f8 ?? ?? ?? ?? 8b 45 08 83 e0 01 89 45 fc 8b 45 08 24 fe 89 45 08 8b 45 08 8b 00 ff 75 08 ff 50 04 ba ?? ?? ?? ?? 8b 4d 08 81 c1 a4 01 00 00 e8 ?? ?? ?? ?? 8b 45 08 c7 80 a8 01 ?? ?? ?? ?? ?? ?? 8b 45 08 dd 05 ?? ?? ?? ?? dd 98 ?? ?? ?? ?? 8b 45 08 dd 05 ?? ?? ?? ?? dd 98 ?? ?? ?? ?? 8d 45 e8 50 8b 45 08 05 a8 01 00 00 50 8b 45 08 05 a4 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 72 00 65 00 61 00 74 00 65 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 00 00 00 00 43 00 6c 00 6f 00 73 00 65 00 00 00 46 00 6f 00 6c 00 64 00 65 00 72 00 45 00 78 00 69 00 73 00 74 00 73 00 00 00 00 00 43 00 72 00 65 00 61 00 74 00 65 00 46 00 6f 00 6c 00 64 00 65 00 72 00 00 00 00 00 46 00 69 00 6c 00 65 00 45 00 78 00 69 00 73 00 74 00 73 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zbot_G_2147647574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zbot.G"
        threat_id = "2147647574"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 00 00 06 00 00 00 47 00 45 00 54 00 00 00 4f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f5 00 00 00 00 1b 0a 00 04 ?? ff 0a 0b 00 0c 00 04 00 ff fc 34 fc f8 64 ff 35 00 ff 3a ?? ff 0c 00 25 6c 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

