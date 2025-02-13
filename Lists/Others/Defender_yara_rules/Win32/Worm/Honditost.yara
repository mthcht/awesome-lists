rule Worm_Win32_Honditost_A_2147644842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Honditost.A"
        threat_id = "2147644842"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Honditost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 72 65 6e 20 4d 73 50 4d 53 4e 53 76 73 2e 64 6c 6c 20 6e 6d 6c 73 76 63 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 63 6f 70 79 20 2f 42 20 6c 73 61 73 72 76 2e 64 6c 6c 2b 7a 69 70 2e 7a 69 70 20 6c 73 61 73 76 73 2e 64 6c 6c 20 2f 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 45 52 45 4e 20 4b 41 4c 49 20 59 41 43 48 20 4b 41 4c 4f 20 47 49 4e 49 2e 2e 2e 21 21 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 75 6b 75 6d 61 6e 42 75 61 74 4b 6f 72 75 70 74 6f 72 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6d 6c 73 76 63 65 78 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "%s\\utama.Ex_" wide //weight: 1
        $x_1_7 = "%s\\yorm.Ex_" wide //weight: 1
        $x_1_8 = "%s\\nmlsvc.Ex_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

