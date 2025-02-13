rule Worm_Win32_Kufgal_A_2147630387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kufgal.A"
        threat_id = "2147630387"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kufgal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 16 8b 44 24 08 56 2b d0 8b f1 8a 0c 02 80 c1 ?? 88 08 40 4e 75 f4}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c0 b1 13 8a 90 ?? ?? ?? ?? 32 d1 88 90 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7c ea}  //weight: 2, accuracy: Low
        $x_2_3 = {68 bd 01 00 00 89 44 24 0c e8 ?? ?? ?? ?? 8d 54 24 04 6a 10 52 56}  //weight: 2, accuracy: Low
        $x_1_4 = "cmd /c taskkill /im alg.exe /f" ascii //weight: 1
        $x_1_5 = "\\Fonts\\bp.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Kufgal_B_2147630388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kufgal.B"
        threat_id = "2147630388"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kufgal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 cf ff 56 e8 ?? ?? ff ff 83 f8 01 1b c0 40 84 c0 0f 84 ?? 00 00 00 6a e0 56 e8 ?? ?? ff ff 3d 02 80 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 ff 30 64 89 20 c7 45 fc ff ff ff ff 6a e0 56 e8 ?? ?? ff ff 3d 02 80 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 53 e8 ?? ?? ff ff 6a 00 53 68 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c0 14 83 c0 02 50 6a 42 e8 ?? ?? ff ff 8b f0 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

