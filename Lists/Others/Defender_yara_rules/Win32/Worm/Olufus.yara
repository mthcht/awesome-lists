rule Worm_Win32_Olufus_A_2147696513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Olufus.A"
        threat_id = "2147696513"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Olufus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "OlfVir1Project" wide //weight: 5
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-32] 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 [0-64] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 65 00 78 00 65 00 [0-16] 53 00 74 00 61 00 72 00 74 00 75 00 70 00 [0-16] 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 00 72 00 69 00 76 00 65 00 4c 00 65 00 74 00 74 00 65 00 72 00 [0-32] 47 00 65 00 74 00 46 00 6f 00 6c 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_7 = {54 00 69 00 6d 00 65 00 72 00 53 00 70 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 41 00 63 00 74 00 69 00 6f 00 6e 00 [0-16] 44 00 72 00 69 00 76 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

