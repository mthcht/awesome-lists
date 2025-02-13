rule Trojan_Win32_Droidpak_A_2147685172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Droidpak.A"
        threat_id = "2147685172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Droidpak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5c 43 72 61 69 6e 69 6e 67 41 70 6b 43 6f 6e 66 69 67 5c 41 56 2d 63 64 6b 2e 61 70 6b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 45 56 49 43 45 3a 31 00 00 00 00 69 63 6f 6e 66 69 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 73 74 61 6c 6c 20 25 73 00 00 00 [0-15] 2e 61 70 6b [0-4] 61 64 62 2e 65 78 65 00 62 65 67 69 6e 20 66 69 6e 64 20 62 7a 20 70 61 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Droidpak_B_2147686830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Droidpak.B"
        threat_id = "2147686830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Droidpak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 61 69 6e 69 6e 67 41 70 6b 43 6f 6e 66 69 67 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 45 56 49 43 45 3a 31 00 00 00 00 69 63 6f 6e 66 69 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 72 69 74 65 20 64 6f 77 6e 6c 6f 61 64 20 66 69 6c 65 20 73 75 63 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {2a 2e 61 70 6b 00 00 00 00 61 64 62 2e 65 78 65 00 65 6e 64 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

