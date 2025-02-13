rule Trojan_Win32_Vochs_A_2147652860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vochs.A"
        threat_id = "2147652860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vochs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 76 63 68 c7 ?? ?? 6f 73 74 2e c7 ?? ?? 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 0b 00 00 00 fc f3 a6 74 65 8d}  //weight: 1, accuracy: High
        $x_1_3 = {b9 7f 00 00 00 32 c0 f2 ae 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

