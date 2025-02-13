rule Trojan_Win32_Yahamam_A_2147696246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yahamam.A!dha"
        threat_id = "2147696246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahamam"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 56 42 54 52 55 4d 67 54 6d 56 30 64 32 39 79 61 79 42 44 62 32 35 75 5a 57 4e 30 61 57 39 75 63 79 42 54 5a 58 4a 32 61 57 4e 6c 63 77 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 55 48 4a 76 64 6d 6c 6b 5a 53 42 54 5a 58 4a 32 61 57 4e 6c 63 79 42 68 62 6d 51 67 54 57 46 75 59 57 64 6c 63 69 42 6d 62 33 49 67 53 56 42 54 52 55 4d 67 54 6d 56 30 64 32 39 79 61 79 42 44 62 32 35 75 5a 57 4e 30 61 57 39 75 63 77 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 62 57 5a 6a 4e 44 45 75 5a 47 78 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 62 57 5a 6a 4e 6a 45 75 5a 47 78 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 63 6e 42 6a 63 6e 51 7a 4d 69 35 6b 62 47 77 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 63 6e 42 6a 63 6e 51 78 4e 69 35 6b 62 47 77 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 53 55 35 44 55 77 3d 3d 00}  //weight: 1, accuracy: High
        $x_2_8 = {00 61 57 35 6a 63 33 5a 6a 00}  //weight: 2, accuracy: High
        $x_2_9 = {00 53 57 31 68 5a 32 56 7a 4c 6d 70 77 5a 77 3d 3d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

