rule Worm_Win32_Heoyon_A_2147654221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Heoyon.A"
        threat_id = "2147654221"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Heoyon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 1f 83 c7 04 e2 f9 5f b8 ff ff ff ff 47 3b 07 75 fb 83 c7 04 ff e7}  //weight: 5, accuracy: High
        $x_5_2 = {33 c9 33 c0 8a 04 39 3c 00 74 09 8a 04 30 88 04 39 41 eb f0}  //weight: 5, accuracy: High
        $x_1_3 = {b8 ef cd ab 89 c1 e9 02 31 07 83 c7 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_4 = {c1 e9 02 b8 89 ab cd ef 31 07 83 c7 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_5 = {5c 77 69 6e 33 32 69 6e 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "Initialize Win32" wide //weight: 1
        $x_1_7 = {5c 73 79 73 74 69 6d 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\W32I\\Update" ascii //weight: 1
        $x_1_9 = {5c 6e 65 74 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {6f 70 65 6e 66 6c 61 73 68 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

