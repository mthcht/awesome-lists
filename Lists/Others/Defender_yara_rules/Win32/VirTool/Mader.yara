rule VirTool_Win32_Mader_C_2147598527_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Mader.C"
        threat_id = "2147598527"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00 00 00 00 6e 74 6b 72 6e 6c 6d 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 53 50 59 3e 50 6a 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 78 7c 28 72 05 8d 34 11 eb 07 c7 45 fc 3e 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {2e 65 78 65 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61}  //weight: 1, accuracy: High
        $x_1_5 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 bc 1e 01 00}  //weight: 1, accuracy: High
        $x_1_6 = {39 5d 1c 56 57 c7 45 d8 00 04 00 00 c7 45 e0 00 02 00 00 c7 45 e4 00 01 00 00 c7 45 e8 01 01 00 00 0f 85}  //weight: 1, accuracy: High
        $x_1_7 = {2e 65 78 65 00 00 00 00 5a 77 45 6e 75 6d 65 72 61 74 65 4b 65 79 00 00 5a 77 45 6e 75 6d 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

