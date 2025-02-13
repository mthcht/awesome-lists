rule Worm_Win32_Mothyfil_A_2147694855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mothyfil.A"
        threat_id = "2147694855"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mothyfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 75 63 6b 5f 75 34 00 66 75 63 6b 5f 75 35 00 43 6c 61 73 73 31 00 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mothyfil_B_2147707162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mothyfil.B"
        threat_id = "2147707162"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mothyfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 65 74 63 6c 69 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 69 73 61 62 6c 65 69 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 75 73 73 79 43 6c 6f 73 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {4b 69 6c 6c 61 70 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 68 61 74 5f 74 68 65 66 75 63 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 64 75 6c 74 6b 69 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

