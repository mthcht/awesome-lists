rule TrojanDownloader_Win32_Bradop_B_2147648934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bradop.B"
        threat_id = "2147648934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 eb 80 3c 2f 2b 72 45 0f b6 c3 80 3c 07 7a 77 3c 0f b6 c3 80 7c 07 01 2b 72 32 0f b6 c3 80 7c 07 01 7a}  //weight: 10, accuracy: High
        $x_10_2 = {c1 e8 06 0a d0 80 e2 3f 0f b6 c2 0f b6 80}  //weight: 10, accuracy: High
        $x_1_3 = "\\Projetos\\newhope\\" ascii //weight: 1
        $x_1_4 = {4e 45 57 48 4f 50 45 00 55 8b ec}  //weight: 1, accuracy: High
        $x_1_5 = {4d 41 49 4e 49 43 4f 4e 00 00 00 00 31 30 39 38 37 37 32 38 38 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bradop_A_2147656233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bradop.A"
        threat_id = "2147656233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradop"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff b9 01 04 00 00 e8 ?? ?? ?? ff 8b 85 f0 f9 ff ff b9 0f 00 00 00 33 d2 e8 ?? ?? ?? ff 8b 85 f4 f9 ff ff 50 b8 ?? ?? ?? ?? 8d 95 ec f9 ff ff e8 ?? ?? ?? ff 8b 95 ec f9 ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {ff b9 01 04 00 00 e8 ?? ?? ?? ff 8b 85 00 fa ff ff b9 0f 00 00 00 33 d2 e8 ?? ?? ?? ff 8b 85 04 fa ff ff 50 8d 95 fc f9 ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 95 fc f9 ff ff}  //weight: 10, accuracy: Low
        $x_1_3 = {08 00 48 00 54 00 4d 00 4c 00 46 00 49 00 4c 00 45 00 06 00 58 00 57 00 52 00 45 00 47 00 43 00}  //weight: 1, accuracy: High
        $x_9_4 = {70 46 3a 46 2f 46 2f [0-2] 32 [0-2] 30 [0-2] 30 [0-2] 2e [0-2] 39 [0-2] 38 [0-2] 2e [0-2] 31 [0-2] 33 [0-2] 36 [0-2] 2e [0-2] 37 [0-2] 32}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bradop_C_2147663248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bradop.C"
        threat_id = "2147663248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 48 00 54 00 4d 00 4c 00 46 00 49 00 4c 00 45 00 06 00 58 00 57 00 52 00 45 00 47 00 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 34 01 84 c0 74 ?? ?? ?? ?? ?? ?? ?? 0f b6 54 3a ff e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 f3 01 47 4e 75}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 01 04 00 00 e8 ?? ?? ?? ?? 8b 85 fc f9 ff ff b9 0f 00 00 00 33 d2 e8 ?? ?? ?? ff 8b 85 00 fa ff ff 50 8d 95 f8 f9 ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 95 f8 f9 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

