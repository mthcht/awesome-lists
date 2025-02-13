rule VirTool_Win32_Sertoh_A_2147686197_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sertoh.A"
        threat_id = "2147686197"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sertoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 65 00 67 00 52 00 65 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Base64_Encrypt_" ascii //weight: 1
        $x_1_3 = {50 6c 75 73 53 70 61 63 65 00 53 70 61 63 65 50 6c 75 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 63 61 6c 50 61 74 68 46 6f 72 53 61 76 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 61 74 68 5f 4f 66 5f 4d 53 49 46 69 6c 65 5f 54 6f 5f 52 75 6e 5f 41 73 5f 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 65 72 76 65 72 75 72 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

