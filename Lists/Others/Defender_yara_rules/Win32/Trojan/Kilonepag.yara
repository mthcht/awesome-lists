rule Trojan_Win32_Kilonepag_A_2147634535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilonepag.A"
        threat_id = "2147634535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilonepag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 51 44 6f 63 74 6f 72 52 74 70 2e 65 78 65 00 52 61 76 2e 65 78 65 00 77 78 43 6c 74 41 69 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 33 32 32 2e 6f 72 67 2f 64 79 6e 64 6e 73 2f 67 65 74 69 70 [0-4] 26 63 3d [0-4] 26 62 3d [0-4] 68 74 74 70 3a 2f 2f [0-31] 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 [0-32] 25 32 45 25 36 33 25 36 46 25 36 44 2f [0-2] 2e 65 78 65 [0-8] (51 51 47 61|73 76 63 68 6f) 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {64 65 6c 20 2a 2a 2a 2a 2a 2a 2a 2a 0d 0a 64 65 6c 20 25 30 00 2a 2a 2a 2a 2a 2a 2a 2a 00 5c [0-4] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_5 = {25 37 36 25 32 45 25 37 39 25 36 31 25 36 46 25 33 36 25 33 33 25 32 45 25 36 33 25 36 46 25 36 44 2f 63 6f 6e 66 69 67 2e 61 73 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

