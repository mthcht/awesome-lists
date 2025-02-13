rule Trojan_Win32_MpTamperThreatSeverity_A_2147768635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperThreatSeverity.A"
        threat_id = "2147768635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperThreatSeverity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-16] 20 00 2d 00 75 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-16] 20 00 2d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-16] 20 00 2d 00 6d 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-16] 20 00 2d 00 68 00}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-16] 20 00 2d 00 73 00 65 00 76 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

