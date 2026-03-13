rule Trojan_Win32_ShinyBastion_A_2147964681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShinyBastion.A"
        threat_id = "2147964681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShinyBastion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 69 72 74 61 75 6c 20 41 6c 6c 6f 63 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 65 6d 43 70 79 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 34 37 65 35 62 66 64 2d 37 66 36 34 2d 34 33 64 66 2d 39 31 33 65 2d 38 38 39 36 37 64 33 62 33 37 38 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

