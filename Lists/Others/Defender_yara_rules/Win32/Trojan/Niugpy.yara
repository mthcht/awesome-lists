rule Trojan_Win32_Niugpy_A_2147691060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Niugpy.A"
        threat_id = "2147691060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Niugpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 7e d2 b1 61 74 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff 78 ea ff ff 75 0a 8b 45 20 e8 ?? ?? ?? ?? eb ?? 81 ff 0e 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 f0 00 ff ff 05 88 ff 00 00 c1 e0 10 50 68 0a 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Niugpy_B_2147691434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Niugpy.B"
        threat_id = "2147691434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Niugpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 7e d2 b1 61 74 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff 78 ea ff ff 75 0a 8b 45 20 e8 ?? ?? ?? ?? eb ?? 81 ff 0e 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 f0 00 ff ff 05 88 ff 00 00 c1 e0 10 50 68 0a 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

