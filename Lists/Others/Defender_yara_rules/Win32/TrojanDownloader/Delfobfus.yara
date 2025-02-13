rule TrojanDownloader_Win32_Delfobfus_A_2147599934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delfobfus.A"
        threat_id = "2147599934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 83 7d ?? 00 75 0a 33 c0 89 45 ?? e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 d0 8a 55 fb 8b 4d fc 8b 5d e8 8a 4c 19 ff 32 d1 e8 ?? ?? ?? ff 8b 55 d0 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d dc 75 d6}  //weight: 1, accuracy: Low
        $x_2_3 = {33 c0 89 45 ?? 83 7d ?? 00 75 0a 33 c0 89 45 ?? e9 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff 85 c0 0f 84 ?? ?? 00 00 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

