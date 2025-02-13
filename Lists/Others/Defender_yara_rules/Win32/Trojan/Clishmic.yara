rule Trojan_Win32_Clishmic_A_2147640445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clishmic.A"
        threat_id = "2147640445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clishmic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 4d 6f 72 70 68 43 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6c 69 63 6b 65 72 20 68 69 64 64 65 6e 20 77 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 61 78 2d 46 6f 72 77 61 72 64 73 3a 20 39 39 39 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 74 74 69 6e 67 73 2f 30 31 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 65 79 73 2f 71 75 65 72 69 65 73 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

