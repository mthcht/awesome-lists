rule Trojan_Win32_Mirsonk_A_2147683843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mirsonk.A"
        threat_id = "2147683843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirsonk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 f7 f9 8a 82 ?? ?? 40 00 8a 96 ?? ?? 40 00 32 d0 88 96 ?? ?? 40 00 46 83 fe 40 7c e1}  //weight: 10, accuracy: Low
        $x_10_2 = {76 20 8b 74 24 1c 8b 5c 24 14 8b 06 03 c3 50 e8 ?? ?? 00 00 3b 44 24 28 74 11 47 83 c6 04 3b fd 72 e8}  //weight: 10, accuracy: Low
        $x_1_3 = {3a 59 d4 e6 00 8d 82 16 55 [0-4] e4 e6 [0-2] 9d 76 5d da}  //weight: 1, accuracy: Low
        $x_1_4 = {7b 49 82 e6 43 89 84 56 0d 34 75 fc f8 49 c7 3b 58 da f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

