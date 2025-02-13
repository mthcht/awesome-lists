rule TrojanDownloader_Win32_Tapivat_B_2147623071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tapivat.B"
        threat_id = "2147623071"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapivat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 03 6a 00 6a 00 68 00 00 00 80 56 ff 15 ?? ?? 00 10 6a 00 50 a3 ?? ?? 00 10 ff 15 ?? ?? 00 10 6a 04 68 00 30 00 00 50 6a 00}  //weight: 3, accuracy: Low
        $x_3_2 = {99 b9 1a 00 00 00 68 dc 05 00 00 f7 f9 8b da 80 c3 41 ff 15 ?? ?? 00 10 6a 00}  //weight: 3, accuracy: Low
        $x_3_3 = {85 c0 74 16 6a 32 ff d7 46 83 fe 05 72 da}  //weight: 3, accuracy: High
        $x_1_4 = {41 6e 74 69 52 65 62 6f 6f 74 44 65 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "ReadOldIniFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tapivat_A_2147623073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tapivat.A"
        threat_id = "2147623073"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapivat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {68 b3 15 00 00 68 ?? ?? 00 10 68 ?? ?? 00 10 ff 15 ?? ?? ?? ?? 8b (d8|f0) b3 15 00 00 (89 75 fc|75 17) 68}  //weight: 6, accuracy: Low
        $x_3_2 = {c6 45 fc 00 64 a1 18 00 00 00 8b 40 30 80 78 02 00 75 02 eb 04 c6 45 fc 01 8a 45 fc}  //weight: 3, accuracy: High
        $x_3_3 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45}  //weight: 3, accuracy: High
        $x_1_4 = "ShieldThread" ascii //weight: 1
        $x_1_5 = "AntiRebootDel" ascii //weight: 1
        $x_1_6 = "ReadOldIniFile" ascii //weight: 1
        $x_1_7 = "BeginWork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

