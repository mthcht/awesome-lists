rule Trojan_Win32_Lipti_A_2147639305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lipti.A"
        threat_id = "2147639305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lipti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 c0 74 0d 81 3e c8 00 00 00 75 05 33 c0 40 eb 02 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 47 10 c6 04 03 00 8b 47 10 8a 0e 88 08 01 5f 10}  //weight: 1, accuracy: High
        $x_1_3 = {8a 44 24 08 0f b6 c0 69 c0 01 01 01 01 8b d1 53 57 8b 7c 24 0c c1 e9 02 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

