rule VirTool_Win64_Uacsspi_A_2147893556_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Uacsspi.A"
        threat_id = "2147893556"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Uacsspi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\127.0.0.1\\pipe\\" ascii //weight: 1
        $x_1_2 = {44 65 6c 65 74 65 53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {51 75 65 72 79 53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 54 6f 6b 65 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 63 63 65 70 74 53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "ntsvcs" ascii //weight: 1
        $x_1_7 = "367abb81-9844-35f1-ad32-98f038001003" ascii //weight: 1
        $x_1_8 = "8a885d04-1ceb-11c9-9fe8-08002b104860" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

