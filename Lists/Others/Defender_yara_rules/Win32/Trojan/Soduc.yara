rule Trojan_Win32_Soduc_A_2147644911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Soduc.A"
        threat_id = "2147644911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Soduc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 63 64 6f 73 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6d 75 63 6f 64 65 2e 63 6d 63 6f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 63 64 6f 73 2e 70 70 64 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {6f 72 74 68 73 65 74 00}  //weight: 1, accuracy: High
        $x_10_5 = {68 74 74 70 3a 2f 2f 31 32 32 2e 32 32 34 2e 39 2e 31 32 30 3a 38 30 32 32 2f 49 6e 73 65 72 74 62 7a 2e 61 73 70 78 3f 6d 63 69 3d 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

