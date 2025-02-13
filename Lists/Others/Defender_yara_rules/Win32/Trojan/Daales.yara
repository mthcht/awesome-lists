rule Trojan_Win32_Daales_A_2147640936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daales.A"
        threat_id = "2147640936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daales"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 75 70 64 2f 78 78 2e 70 68 70 3f 69 64 3d ?? ?? ?? 26 73 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 75 70 64 2f 63 68 65 63 6b 2e 70 68 70 3f 76 65 72 3d 30 26 63 76 65 72 3d 30 26 69 64 3d ?? ?? ?? ?? 64 6f 77 6e 6c 6f 61 64 00 73 75 63 63 65 73 73 00 31 30 32 33 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 44 69 61 6c 65 72 2e 64 6c 6c 00 41 74 74 65 6d 70 74 43 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

