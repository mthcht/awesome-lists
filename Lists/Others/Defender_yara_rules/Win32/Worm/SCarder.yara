rule Worm_Win32_SCarder_2147681769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SCarder"
        threat_id = "2147681769"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SCarder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 d0 00 00 00 00 c7 45 d4 0b 00 00 00 89 45 ?? c7 45 d4 15 07 00 00 89 45 ?? 83 7d ?? 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 e8 8b 08 83 c1 01 8b 55 e8 89 0a 8b 45 f8 3b 45 14}  //weight: 1, accuracy: High
        $x_5_3 = "8+fsdfse'ww" ascii //weight: 5
        $x_5_4 = "e2342242flfEBG" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

