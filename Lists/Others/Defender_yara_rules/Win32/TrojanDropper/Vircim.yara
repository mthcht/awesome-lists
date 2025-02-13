rule TrojanDropper_Win32_Vircim_A_2147631476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vircim.A"
        threat_id = "2147631476"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vircim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 25 00 73 00 22 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 61 00 7a 00 2e 00 70 00 68 00 70 00 3f 00 6f 00 3d 00 25 00 64 00 26 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 74 00 65 00 70 00 3d 00 25 00 64 00 22 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 63 20 63 72 65 61 74 65 20 25 73 20 74 79 70 65 3d 20 6b 65 72 6e 65 6c 20 62 69 6e 70 61 74 68 3d 20 22 25 73 22 20 73 74 61 72 74 3d 20 61 75 74 6f 00 63 6d 64 20 2f 43 20 63 6f 70 79 20 22 25 73 22 20 22 25 73 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

