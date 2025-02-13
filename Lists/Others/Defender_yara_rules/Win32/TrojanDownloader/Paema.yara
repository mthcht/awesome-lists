rule TrojanDownloader_Win32_Paema_A_2147646049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Paema.A"
        threat_id = "2147646049"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Paema"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 24 28 50 e8 ?? ?? ?? ?? 59 84 c0 74 07 68 ?? ?? ?? ?? eb 05 68 ?? ?? ?? ?? ff d6 eb e1}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f3 8b 4f 14 89 4d ec d1 6d ec 8b 55 ec 3b d0 76 0e 8b 75 e8 8b c6 2b c2 3b c8 77 03 8d 34 0a 83 65 fc 00 8d 46 01 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

