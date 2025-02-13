rule TrojanDownloader_Win32_Pelfpoi_L_2147645818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pelfpoi.L"
        threat_id = "2147645818"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pelfpoi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[{000214A0-0000-0000-C000-000000000046}]" ascii //weight: 1
        $x_1_2 = "atbfsh.exe" ascii //weight: 1
        $x_2_3 = {f7 ff eb 0d ba 01 00 00 00 8b 45 f4 e8 ?? ?? 00 00 47 4e 0f 85 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {b2 01 a1 b8 d3 48 00 e8 ?? ?? fd ff 89 45 fc 8b 45 fc e8 ?? ?? fd ff 83 c0 70 ba ?? ?? 4b 00 e8 ?? ?? f4 ff b2 01 a1 b8 77 41 00 e8 ?? ?? f4 ff}  //weight: 2, accuracy: Low
        $x_2_5 = {8d 45 fc 50 8d 55 e8 8b 43 30 e8 ?? ?? ff ff 8b 45 e8 89 45 ec c6 45 f0 0b 8d 55 e4 8b 43 30 e8 ?? ?? ff ff 8b 45 e4 89 45 f4 c6 45 f8 0b 8d 45 ec 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

