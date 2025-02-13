rule TrojanDownloader_Win32_Leckbrio_B_2147644262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Leckbrio.B"
        threat_id = "2147644262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Leckbrio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 03 b8 1d 00 00 00 e8 ?? ?? ?? ?? 40 ba ?? ?? ?? ?? 8a 44 02 ff 8b 13 88 82 ?? ?? ?? ?? ff 03 83 3b 1f 75 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 3a 00 00 00 e8 ?? ?? ?? ?? ff b5 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 2a 00 00 00 e8 ?? ?? ?? ?? ff b5 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3b 4d 0f 85 ?? ?? ?? ?? 6a 00 6a 00 6a 01 6a 00 6a 00 68 00 00 00 40 8b 45 e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

