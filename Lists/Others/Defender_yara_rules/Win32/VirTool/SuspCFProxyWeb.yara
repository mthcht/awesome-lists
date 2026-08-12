rule VirTool_Win32_SuspCFProxyWeb_A_2147976035_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspCFProxyWeb.A"
        threat_id = "2147976035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCFProxyWeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 65 72 2d 54 69 6d 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 70 6f 72 74 2d 54 6f 4e 65 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6c 6f 75 64 66 6c 61 72 65 43 66 2d 52 61 79 41 6c 74 2d 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {22 6d 61 63 68 69 6e 65 5f 67 75 69 64 22 3a 00}  //weight: 1, accuracy: High
        $x_1_5 = {22 68 6f 73 74 6e 61 6d 65 22 3a 00}  //weight: 1, accuracy: High
        $x_1_6 = {22 6f 73 22 3a 00}  //weight: 1, accuracy: High
        $x_1_7 = {22 76 65 72 73 69 6f 6e 22 3a 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 70 67 72 61 64 65 3a 20 77 65 62 73 6f 63 6b 65 74 0d 0a 7b 22 72 65 70 6f 72 74 5f 74 6f 22 3a 22 63 66 2d 6e 65 6c 22 2c 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

