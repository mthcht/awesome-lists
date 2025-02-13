rule TrojanClicker_Win32_Eiderf_A_2147655427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Eiderf.gen!A"
        threat_id = "2147655427"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Eiderf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 8c 04 08 04 00 00 83 c0 01 3d 00 01 00 00 7c e8 56 57}  //weight: 2, accuracy: High
        $x_2_2 = {2b c2 83 f8 05 76 33 8b 15 ?? ?? ?? ?? 69 d2 7c 01 00 00 8d 44 24 14 8b c8 2b d1 8d 92}  //weight: 2, accuracy: Low
        $x_1_3 = "TEST 06.07.11" ascii //weight: 1
        $x_1_4 = "clickrandomlink=" ascii //weight: 1
        $x_1_5 = "Sertified" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

