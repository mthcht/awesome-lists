rule Trojan_Win32_Gyplit_A_2147646530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gyplit.A"
        threat_id = "2147646530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gyplit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 10 32 d9 88 1c 10 40 3b c6 7c cc}  //weight: 1, accuracy: High
        $x_1_2 = {74 52 b9 11 00 00 00 33 c0 8d 7c 24 ?? 8d 54 24 ?? f3 ab}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 9c 04 bc 02 00 00 80 f3 47 88 9c 04 bc 02 00 00 40 3b c1 72 ea 8d 4c 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

