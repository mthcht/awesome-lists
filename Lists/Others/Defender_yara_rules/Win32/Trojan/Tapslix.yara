rule Trojan_Win32_Tapslix_A_2147626401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapslix.A"
        threat_id = "2147626401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapslix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 14 18 8a 14 19 32 d0 88 14 19 41 3b ce 7c e0}  //weight: 1, accuracy: High
        $x_1_2 = {80 f9 23 74 10 8b 94 24 ?? ?? ?? ?? 40 3b c3 88 4c 10 0b 7c e4}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 c6 44 24 ?? 65 c6 44 24 ?? 78 c6 44 24 ?? 69 c6 44 24 ?? 74 c6 44 24 ?? 0d c6 44 24 ?? 0a}  //weight: 1, accuracy: Low
        $x_1_4 = "jejxjej.jdjm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

