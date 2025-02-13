rule Worm_Win32_Bolkc_A_2147652670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bolkc.A"
        threat_id = "2147652670"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bolkc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 33 c9 8a 4c 10 01 c1 f9 03 88 8d 5c ff ff ff 8b 55 f8 6b d2 03 8b 45 f4}  //weight: 2, accuracy: High
        $x_2_2 = {49 4e 33 44 43 4c 41 53 53 00 00 11 00 73 76 63 68 6f 73 74}  //weight: 2, accuracy: Low
        $x_1_3 = "oleg--n" ascii //weight: 1
        $x_1_4 = "?\\DP(?)?-?+??" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

