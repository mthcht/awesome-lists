rule TrojanDropper_Win32_Jomloon_A_2147616354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jomloon.A"
        threat_id = "2147616354"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jomloon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 02 6a 00 6a 00 68 ff 03 1f 00 ?? 8b ce 8b e8 e8 ?? ?? ?? ?? 8b f8 83 ff ff [0-6] 8b ?? 24 ?? 8d ?? 24 ?? ?? 55 ?? 57 8b ce e8 ?? ?? ?? ?? 6a 02 6a 00 6a 00 57 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 25 ff 00 00 00 89 4d 0c 89 45 08 50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

