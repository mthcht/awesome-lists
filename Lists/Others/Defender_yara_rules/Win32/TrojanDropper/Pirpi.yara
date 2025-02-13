rule TrojanDropper_Win32_Pirpi_B_2147639902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pirpi.B"
        threat_id = "2147639902"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 3b 4d 10 7d 2a 8b 55 fc 8a 44 15 ?? 32 45 08 8b 4d fc 88 44 0d 00 8b 55 0c 03 55 fc 8b 45 fc 8a 0a 32 4c 05 00 8b 55 0c 03 55 fc 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d f4 00 74 14 81 7d f4 ?? ?? ?? ?? 74 0b 8b 45 f4 35 00 89 45 f4 6a 00 8d 8d ?? ?? ff ff 51 6a 04 8d 55 f4 52 8b 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

