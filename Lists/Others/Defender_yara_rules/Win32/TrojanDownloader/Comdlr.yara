rule TrojanDownloader_Win32_Comdlr_A_2147628337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Comdlr.A"
        threat_id = "2147628337"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Comdlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 55 e8 03 42 24 8b 55 e0 03 d2 03 c2 66 8b 00 66 89 45 de 66 83 45 de 03 8b 45 fc 8b 55 e8 03 42 1c 0f b7 55 de c1 e2 02 03 c2 89 45 d8 8b 45 d8 8b 00 03 45 fc 89 45 f4 eb 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 01 6a 00 6a 02 68 00 00 00 40 8b 45 f8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 ec 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 45 f0 8b 45 d8 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Comdlr_B_2147629875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Comdlr.B"
        threat_id = "2147629875"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Comdlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 55 e8 03 42 24 8b 55 e0 03 d2 03 c2 66 8b 00 66 89 45 de 66 83 45 de 03 8b 45 fc 8b 55 e8 03 42 1c 0f b7 55 de c1 e2 02 03 c2 89 45 d8 8b 45 d8 8b 00 03 45 fc 89 45 f4 eb 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 01 6a 00 6a 02 68 00 00 00 40 8b 45 f8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 ec 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

