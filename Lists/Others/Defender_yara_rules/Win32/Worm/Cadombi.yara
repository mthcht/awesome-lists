rule Worm_Win32_Cadombi_A_2147618507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cadombi.A"
        threat_id = "2147618507"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadombi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 f0 cd a1 41 67 e8 ?? ?? ?? ?? 8d 45 c8 c7 04 24 bb 01 00 00 50 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 55 e8 8d 44 05 0c 94 53 68 2e 65 78 65 68 5c 63 6d 64 94 31 d2 8d 45 cc}  //weight: 2, accuracy: High
        $x_1_3 = {68 bd 01 00 00 50 e8 ?? ?? ?? ?? 59 85 c0 59 74 08 89 9d ?? ?? ff ff eb 22 8d 85 ?? ?? ff ff 68 8b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 66 0f 8f ?? ?? 00 00 0f 84 ?? ?? 00 00 83 f8 4c 0f 8f ?? ?? 00 00 0f 84 ?? ?? 00 00 83 f8 ff 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

