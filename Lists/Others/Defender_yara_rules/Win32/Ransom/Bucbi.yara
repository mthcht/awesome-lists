rule Ransom_Win32_Bucbi_A_2147688496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bucbi.A"
        threat_id = "2147688496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bucbi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 72 61 6e 73 61 63 74 69 6f 6e 20 77 61 73 20 73 65 6e 74 20 61 6e 64 20 77 69 6c 6c 20 62 65 20 76 65 72 69 66 69 65 64 20 73 6f 6f 6e 2e 00 54 72 61 6e 73 61 63 74 69 6f 6e 20 49 44 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 73 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = {41 6e 79 20 61 74 74 65 6d 70 74 20 74 6f 20 72 65 6d 6f 76 65 20 6f 72 20 64 61 6d 61 67 65 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 20 77 69 6c 6c 20 6c 65 61 64 20 74 6f 20 74 68 65 20 69 6d 6d 65 64 69 61 74 65 20 64 65 73 74 72 75 63 74 69 6f 6e 20 6f 66 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 20 62 79 20 73 65 72 76 65 72 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6f 64 74 00 6f 64 73 00 6f 64 70 00 6f 64 6d 00 6f 64 63 00 6f 64 62 00 64 6f 63 00 77 70 73 00 78 6c 73 00 78 6c 6b 00 70 70 74 00 6d 64 62 00 70 73 74 00 64 77 67 00 64 78 66 00 64 78 67 00 77 70 64 00 72 74 66 00 77 62 32 00 6d 64 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d 00 65 00 00 00 20 00 2d 00 64 00 00 00 3a 00 00 00 25 59 2d 25 6d 2d 25 64 20 5b 25 58 5d 00}  //weight: 1, accuracy: High
        $x_1_6 = {80 b4 04 20 01 00 00 17 40 3d 86 02 00 00 72 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

