rule VirTool_Win32_CertUtlRegHive_A_2147796984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CertUtlRegHive.A"
        threat_id = "2147796984"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CertUtlRegHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\certutil.exe" wide //weight: 3
        $x_1_2 = " -encode" wide //weight: 1
        $x_1_3 = {5c 00 5c 00 3f 00 5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 [0-4] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 41 00 4d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 5c 00 3f 00 5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 [0-4] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 5c 00 3f 00 5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 [0-4] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

