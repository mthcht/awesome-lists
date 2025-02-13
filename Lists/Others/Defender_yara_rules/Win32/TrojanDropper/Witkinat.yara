rule TrojanDropper_Win32_Witkinat_A_2147630731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Witkinat.A"
        threat_id = "2147630731"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Witkinat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 03 ff ?? 75 09 c7 45 ?? 02 00 00 00 eb 07 c7 45 ?? 03 00 00 00 8b 45 0c 50 53}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 fd 8a 82 ?? ?? ?? ?? 8b 16 8a 14 0a 32 c2 8b 16 88 04 0a 41 4b 75 e4 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 6e 6f 68 6f 6d 65 00 69 65 78 70 6c 6f 72 65 [0-5] 6f 70 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 75 13 83 7d f8 02 75 17 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0a 8d 45 f4 8b d7 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 04 80 33 ?? 43 81 fb ?? ?? ?? ?? 75 f4 6a 00 68 ?? ?? ?? ?? 6a 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

