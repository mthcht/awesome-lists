rule Trojan_Win32_Dipverdle_A_2147683017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dipverdle.A"
        threat_id = "2147683017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipverdle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 eb 06 8d 45 ?? 8b d3 83 e2 3f 42 8b [0-5] 8a 54 11 ff e8}  //weight: 2, accuracy: Low
        $x_1_2 = {49 64 65 6e 74 69 74 69 65 73 5c 49 64 65 6e 74 69 74 79 5f 54 44 4e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 70 73 73 76 63 20 73 74 61 72 74 3d 44 69 73 61 62 6c 65 64 00 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {75 69 64 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 76 65 72 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 64 6c 3d 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 64 6c 3d 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 64 69 70 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

