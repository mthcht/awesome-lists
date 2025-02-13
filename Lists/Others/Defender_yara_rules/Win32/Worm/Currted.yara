rule Worm_Win32_Currted_A_2147650647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Currted.A"
        threat_id = "2147650647"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Currted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 79 20 42 61 62 79 2e 65 78 65 00 43 61 6e 61 64 61 00 46 69 6c 65 20 43 75 72 72 75 70 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 44 72 69 76 65 72 73 5c 65 74 63 5c 43 61 6e 61 64 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 61 6e 61 64 61 2e 65 78 65 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

