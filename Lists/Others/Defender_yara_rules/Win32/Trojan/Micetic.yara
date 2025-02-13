rule Trojan_Win32_Micetic_A_2147658653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Micetic.gen!A"
        threat_id = "2147658653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Micetic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 40 83 fa ?? 7c f6 03 00 80 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 72 00 25 73 20 2d 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 8f 95 86 93 8f 86 95 64 90 8f 8f 86 84 95 62}  //weight: 1, accuracy: High
        $x_1_4 = {80 3b e9 75 04 33 c0 eb 6a e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

