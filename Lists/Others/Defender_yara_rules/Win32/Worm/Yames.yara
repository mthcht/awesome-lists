rule Worm_Win32_Yames_A_2147648339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yames.A"
        threat_id = "2147648339"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 20 00 59 00 61 00 68 00 6f 00 6f 00 21 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 79 00 6d 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 79 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 00 3a 00 5c 00 79 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

