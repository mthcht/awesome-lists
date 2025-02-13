rule PWS_Win32_Sapbexts_A_2147628244_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sapbexts.A"
        threat_id = "2147628244"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sapbexts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 fa 61 88 17 7c 05 80 fa 7a 7e 12 ff 15 ?? ?? ?? ?? 6a 18 33 d2 59 f7 f1 80 c2 61}  //weight: 2, accuracy: Low
        $x_2_2 = {80 38 57 75 1c 80 78 01 49 75 16 80 78 02 43 75 10 80 78 03 4b 75 0a}  //weight: 2, accuracy: High
        $x_2_3 = {04 41 53 53 88 03 c6 43 01 3a c6 43 02 5c c6 43 03 00}  //weight: 2, accuracy: High
        $x_1_4 = {63 6f 70 79 20 2f 79 20 22 25 53 59 53 54 45 4d 52 4f 4f 54 25 5c 73 79 73 74 65 6d 33 32 5c 70 69 6e 67 2e 65 78 65 22 20 22 25 54 45 4d 50 25 5c 73 6d 73 73 2e 65 78 65 22 00}  //weight: 1, accuracy: High
        $x_1_5 = {2a 2a 2a 21 21 21 50 41 53 53 4e 45 58 54 21 21 21 2a 2a 2a 00}  //weight: 1, accuracy: High
        $x_1_6 = {6e 6f 20 49 50 20 6f 72 20 41 56 50 20 77 6f 72 6b 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

