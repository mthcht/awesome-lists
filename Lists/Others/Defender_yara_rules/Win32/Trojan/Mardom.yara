rule Trojan_Win32_Mardom_SX_2147947304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mardom.SX!MTB"
        threat_id = "2147947304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mardom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 7e 04 00 00 04 8e 69 28 06 00 00 06 0a}  //weight: 3, accuracy: High
        $x_2_2 = {06 d0 04 00 00 02 28 11 00 00 0a 28 ?? 00 00 0a 74 04 00 00 02}  //weight: 2, accuracy: Low
        $x_1_3 = {0a 26 14 14 28 ?? 00 00 0a 26 14 14 28 ?? 00 00 0a 26 14 14 28 ?? 00 00 0a 26}  //weight: 1, accuracy: Low
        $x_1_4 = {07 7e 04 00 00 04 8e 69 1f 40 12 00 28 05 00 00 06 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

