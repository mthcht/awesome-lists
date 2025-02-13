rule VirTool_Win32_PoshC2_G_2147826893_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PoshC2.G"
        threat_id = "2147826893"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PoshC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 4d 53 3d [0-8] 45 54 57 3d [0-8] 4e 54 44 3d [0-16] 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 6e 74 64 6c 6c 2e 64 6c 6c [0-8] 2e 74 65 78 74 [0-48] 43 4c 52 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 [0-8] 61 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 [0-8] 6e 74 64 6c 6c [0-8] 45 74 77 45 76 65 6e 74 57 72 69 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

