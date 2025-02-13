rule HackTool_Win32_Lsascan_2147696306_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Lsascan"
        threat_id = "2147696306"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lsascan"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 63 68 6f 20 50 72 65 73 73 20 61 6e 79 20 4b 65 79 20 74 6f 20 45 58 49 54 20 2e 2e 2e 20 26 20 70 61 75 73 65 20 3e 20 6e 75 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "UserName: %S" ascii //weight: 1
        $x_1_3 = "LogonDomain: %S" ascii //weight: 1
        $x_1_4 = {47 65 74 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 42 79 4e 61 6d 65 20 66 61 69 6c 20 21 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 6e 61 62 6c 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 20 66 61 69 6c 20 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

