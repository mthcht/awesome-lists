rule HackTool_Win32_ICrypt_A_2147628309_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ICrypt.A"
        threat_id = "2147628309"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ICrypt"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 4e 54 20 75 73 65 72 73 3a 20 50 6c 65 61 73 65 20 6e 6f 74 65 20 74 68 61 74 20 68 61 76 69 6e 67 20 74 68 65 20 57 69 6e 49 63 65 2f 53 6f 66 74 49 63 65 0d 0a 73 65 72 76 69 63 65 20 69 6e 73 74 61 6c 6c 65 64 20 6d 65 61 6e 73 20 74 68 61 74 20 79 6f 75 20 61 72 65 20 72 75 6e 6e 69 6e 67 20 61 20 64 65 62 75 67 67 65 72 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 43 72 79 70 74 2e 69 43 54 65 78 74 42 6f 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 00 75 00 6c 00 6c 00 79 00 75 00 6e 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

