rule Trojan_Win32_Redyms_A_2147678590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redyms.A"
        threat_id = "2147678590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redyms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 2f 61 6f 6c 2f 73 65 61 72 63 68 3f 00}  //weight: 10, accuracy: High
        $x_1_2 = {8b 75 08 56 ff 15 ?? ?? ?? ?? 8b 40 28 68 42 50 57 46 6a 01 03 c6 56 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 08 ff 15 ?? ?? ?? ?? 8b 40 28 03 45 08 68 42 50 57 46 6a 01 ff 75 08 ff d0}  //weight: 1, accuracy: Low
        $x_10_4 = {b8 00 01 08 84 75 05 b8 00 31 88 84 8b 57 04 6a 00 50 8b 45 ?? 6a 00 6a 00 6a 00 50 52 51 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

