rule TrojanDropper_Win32_Dooxud_A_2147654535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dooxud.A"
        threat_id = "2147654535"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dooxud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 03 85 ?? ?? ff ff 8a 10 32 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9 ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c0 66 8b 02 3d 4d 5a 00 00 74 05 e9 ?? ?? 00 00 8b 0d ?? ?? ?? 00 8b 55 0c 03 51 3c 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 81 38 50 45 00 00 74 05 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 66 8b 11 81 fa 4d 5a 00 00 74 05 e9 ?? ?? 00 00 a1 ?? ?? ?? 00 8b 4d 0c 03 48 3c 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 81 3a 50 45 00 00 74 05 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

